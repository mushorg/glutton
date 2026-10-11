package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/spice"
)

// spiceMaxPayload bounds the bytes kept from a non-SPICE first read.
const spiceMaxPayload = 4096

// spiceCommonCaps are the common caps spice-server advertises with ticketing
// on: auth selection, SPICE auth and mini headers. SASL is not offered.
var spiceCommonCaps = []uint32{1<<spice.CapProtocolAuthSelection | 1<<spice.CapAuthSpice | 1<<spice.CapMiniHeader}

// spiceMainCaps are the main channel caps of spice-server: semi-seamless
// migration, name and UUID, agent connected tokens, seamless migration.
var spiceMainCaps = []uint32{0x0f}

// spiceKey is the RSA key pair whose public half goes into every link reply
// and which decrypts the client's ticket. spice-server makes one per link;
// generating it once per process keeps connection floods cheap. Tests swap it.
var spiceKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, spice.KeyBits)
})

type parsedSPICE struct {
	Direction     string `json:"direction,omitempty"`
	Command       string `json:"command,omitempty"`
	Status        string `json:"status,omitempty"`
	Version       string `json:"version,omitempty"`
	ConnectionID  uint32 `json:"connection_id,omitempty"`
	ChannelType   string `json:"channel_type,omitempty"`
	ChannelID     uint8  `json:"channel_id,omitempty"`
	CommonCaps    string `json:"common_caps,omitempty"`
	ChannelCaps   string `json:"channel_caps,omitempty"`
	AuthMechanism string `json:"auth_mechanism,omitempty"`
	// the ticket is a guessing attempt and recorded as decrypted
	Password string `json:"password,omitempty"`
	Payload  []byte `json:"payload,omitempty"`
}

type spiceServer struct {
	events []parsedSPICE
	conn   net.Conn
	reader *bufio.Reader
}

// readFull reads n bytes and returns what arrived, also on error.
func (s *spiceServer) readFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := io.ReadFull(s.reader, buf)
	return buf[:got], err
}

// recordPartial keeps the bytes of a message cut short by a read error.
func (s *spiceServer) recordPartial(f parsedSPICE) {
	if len(f.Payload) > 0 {
		s.record(f)
	}
}

func (s *spiceServer) record(f parsedSPICE) {
	f.Direction = "read"
	s.events = append(s.events, f)
}

func (s *spiceServer) write(f parsedSPICE) error {
	if _, err := s.conn.Write(f.Payload); err != nil {
		return err
	}
	f.Direction = "write"
	s.events = append(s.events, f)
	return nil
}

func (s *spiceServer) linkError(code uint32) error {
	return s.write(parsedSPICE{Command: "LinkReply", Status: spice.LinkErrorName(code), Payload: spice.BuildLinkError(code)})
}

// HandleSPICE answers the SPICE link stage like spice-server with ticketing
// on: it accepts the link message with an RSA public key, decrypts the
// client's ticket into the password it tried and denies it.
func HandleSPICE(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &spiceServer{events: []parsedSPICE{}, conn: conn, reader: bufio.NewReader(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("spice", conn, md, helpers.FirstOrEmpty[parsedSPICE](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "spice"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SPICE connection", slog.String("protocol", "spice"), producer.ErrAttr(err))
		}
	}()

	var err error
	endReason, err = server.serve(ctx, md, logger, h)
	return err
}

func (s *spiceServer) serve(ctx context.Context, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (string, error) {
	timeout := func() bool {
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "spice"), producer.ErrAttr(err))
			return false
		}
		return true
	}
	readEnd := func(err error) string {
		logger.Debug("Failed to read SPICE", slog.String("protocol", "spice"), producer.ErrAttr(err))
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// the client closed partway through a message
			return connection.EndClientClose
		}
		return connection.EndReasonFromRead(err)
	}
	writeEnd := func(err error) (string, error) {
		logger.Error("Failed to write SPICE response", slog.String("protocol", "spice"), producer.ErrAttr(err))
		return connection.EndWriteError, nil
	}
	// link errors end the link, as in spice-server
	refuse := func(code uint32) (string, error) {
		if err := s.linkError(code); err != nil {
			return writeEnd(err)
		}
		return connection.EndHandlerClose, nil
	}

	if !timeout() {
		return connection.EndTimeout, nil
	}
	head, err := s.readFull(spice.HeaderLen)
	if err != nil {
		s.recordPartial(parsedSPICE{Payload: head})
		return readEnd(err), nil
	}
	hdr, err := spice.ParseHeader(head)
	if errors.Is(err, spice.ErrMagic) {
		// not a SPICE client; keep whatever else it already sent
		extra, _ := s.reader.Peek(min(s.reader.Buffered(), spiceMaxPayload-len(head)))
		s.record(parsedSPICE{Payload: append(head, extra...)})
		return refuse(spice.LinkErrInvalidMagic)
	}
	if err != nil {
		s.record(parsedSPICE{Command: "LinkMess", Version: hdr.Version(), Payload: head})
		return refuse(spice.LinkErrorFor(err))
	}

	if !timeout() {
		return connection.EndTimeout, nil
	}
	body, err := s.readFull(int(hdr.Size))
	if err != nil {
		s.record(parsedSPICE{Command: "LinkMess", Version: hdr.Version(), Payload: append(head, body...)})
		return readEnd(err), nil
	}
	mess, err := spice.ParseLinkMess(body)
	s.record(parsedSPICE{
		Command:      "LinkMess",
		Version:      hdr.Version(),
		ConnectionID: mess.ConnectionID,
		ChannelType:  spice.ChannelTypeName(mess.ChannelType),
		ChannelID:    mess.ChannelID,
		CommonCaps:   spice.CapsHex(mess.CommonCaps),
		ChannelCaps:  spice.CapsHex(mess.ChannelCaps),
		Payload:      append(head, body...),
	})
	if err != nil {
		return refuse(spice.LinkErrInvalidData)
	}

	host, port, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	logger.Info(
		"spice link",
		slog.String("handler", "spice"),
		slog.String("protocol", "spice"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("channel_type", spice.ChannelTypeName(mess.ChannelType)),
	)

	priv, err := spiceKey()
	if err != nil {
		logger.Error("Failed to generate SPICE key", slog.String("protocol", "spice"), producer.ErrAttr(err))
		return connection.EndHandlerClose, err
	}
	pub, err := spice.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		logger.Error("Failed to encode SPICE key", slog.String("protocol", "spice"), producer.ErrAttr(err))
		return connection.EndHandlerClose, err
	}
	var channelCaps []uint32
	if mess.ChannelType == spice.ChannelMain {
		channelCaps = spiceMainCaps
	}
	reply, err := spice.BuildLinkReply(pub, spiceCommonCaps, channelCaps)
	if err != nil {
		return connection.EndHandlerClose, err
	}
	if err := s.write(parsedSPICE{
		Command:     "LinkReply",
		Status:      spice.LinkErrorName(spice.LinkErrOK),
		CommonCaps:  spice.CapsHex(spiceCommonCaps),
		ChannelCaps: spice.CapsHex(channelCaps),
		Payload:     reply,
	}); err != nil {
		return writeEnd(err)
	}

	// clients that set auth selection name the mechanism before the ticket
	if mess.HasCommonCap(spice.CapProtocolAuthSelection) {
		if !timeout() {
			return connection.EndTimeout, nil
		}
		data, err := s.readFull(4)
		if err != nil {
			s.recordPartial(parsedSPICE{Command: "AuthMechanism", Payload: data})
			return readEnd(err), nil
		}
		mech := binary.LittleEndian.Uint32(data)
		s.record(parsedSPICE{Command: "AuthMechanism", AuthMechanism: spice.AuthMechanismName(mech), Payload: data})
		if mech != spice.AuthSpice {
			return refuse(spice.LinkErrInvalidData)
		}
	}

	if !timeout() {
		return connection.EndTimeout, nil
	}
	ticket, err := s.readFull(spice.TicketLen)
	if err != nil {
		s.recordPartial(parsedSPICE{Command: "Ticket", Payload: ticket})
		return readEnd(err), nil
	}
	frame := parsedSPICE{Command: "Ticket", Payload: ticket}
	if password, err := spice.DecryptTicket(priv, ticket); err != nil {
		logger.Debug("Failed to decrypt SPICE ticket", slog.String("protocol", "spice"), producer.ErrAttr(err))
	} else {
		frame.Password = password
	}
	s.record(frame)
	logger.Info(
		"spice login attempt",
		slog.String("handler", "spice"),
		slog.String("protocol", "spice"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("password", frame.Password),
	)

	// every ticket is wrong; spice-server closes the link after the result
	if err := s.write(parsedSPICE{
		Command: "LinkResult",
		Status:  spice.LinkErrorName(spice.LinkErrPermissionDenied),
		Payload: spice.BuildLinkResult(spice.LinkErrPermissionDenied),
	}); err != nil {
		return writeEnd(err)
	}
	return connection.EndHandlerClose, nil
}
