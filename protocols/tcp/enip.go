package tcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/mushorg/glutton/protocols/tcp/enip"
)

const (
	// maxENIPRequests caps the requests answered per session.
	maxENIPRequests = 32
	// maxENIPBody caps the encapsulation data read per request. List and
	// session commands carry at most a few bytes.
	maxENIPBody = 4096
	// defaultENIPPort is advertised when the local port is unknown.
	defaultENIPPort = 44818
)

// scrubbedSensorIP replaces the sensor address advertised in ListIdentity
// replies when the frame is recorded; the sanitizer only rewrites text.
var scrubbedSensorIP = net.IPv4(1, 2, 3, 4)

var (
	// enipSerial is the identity serial number, random per sensor process so
	// sensors do not share a fingerprint. Tests replace it.
	enipSerial = sync.OnceValue(randomUint32)
	// enipSessionHandle assigns RegisterSession handles. Tests replace it.
	enipSessionHandle = randomUint32
)

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x00c0ffee
	}
	if v := binary.LittleEndian.Uint32(b[:]); v != 0 {
		return v
	}
	return 1
}

// parsedENIP is one encapsulation message of the session.
type parsedENIP struct {
	Direction     string `json:"direction,omitempty"`      // "read" (from attacker) or "write" (from honeypot)
	Command       string `json:"command,omitempty"`        // encapsulation command, e.g. ListIdentity; "malformed" for a partial header
	SessionHandle uint32 `json:"session_handle,omitempty"` // header session handle
	SenderContext string `json:"sender_context,omitempty"` // hex of the 8-byte sender context (Censys: 4f495359534e4543, "OISYSNEC")
	Status        string `json:"status,omitempty"`         // write encapsulation status, e.g. success, invalid_command
	Payload       []byte `json:"payload,omitempty"`
	Truncated     bool   `json:"truncated,omitempty"` // body over maxENIPBody or cut short by disconnect
}

type enipServer struct {
	events  []parsedENIP
	conn    net.Conn
	session uint32 // registered session handle, 0 when none
}

var errENIPOversize = errors.New("enip: encapsulation length over cap")

// read returns the next request header and its data. Partial and oversize
// requests are recorded before the error is returned.
func (s *enipServer) read() (enip.Header, []byte, error) {
	raw := make([]byte, enip.HeaderSize)
	n, err := io.ReadFull(s.conn, raw)
	if err != nil {
		if n > 0 {
			s.events = append(s.events, parsedENIP{Direction: "read", Command: "malformed", Payload: raw[:n], Truncated: true})
		}
		return enip.Header{}, nil, err
	}
	hdr, _ := enip.ParseHeader(raw)
	frame := parsedENIP{
		Direction:     "read",
		Command:       enip.CommandName(hdr.Command),
		SessionHandle: hdr.SessionHandle,
		SenderContext: hex.EncodeToString(hdr.SenderContext[:]),
	}
	if hdr.Length > maxENIPBody {
		frame.Payload = raw
		frame.Truncated = true
		s.events = append(s.events, frame)
		return hdr, nil, errENIPOversize
	}
	body := make([]byte, hdr.Length)
	n, err = io.ReadFull(s.conn, body)
	frame.Payload = append(raw, body[:n]...)
	frame.Truncated = err != nil
	s.events = append(s.events, frame)
	return hdr, body, err
}

// write sends data and records it, with recorded in place of data when the
// wire bytes carry the sensor address.
func (s *enipServer) write(data, recorded []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	if recorded == nil {
		recorded = data
	}
	hdr, _ := enip.ParseHeader(data)
	s.events = append(s.events, parsedENIP{
		Direction:     "write",
		Command:       enip.CommandName(hdr.Command),
		SessionHandle: hdr.SessionHandle,
		SenderContext: hex.EncodeToString(hdr.SenderContext[:]),
		Status:        enip.StatusName(hdr.Status),
		Payload:       recorded,
	})
	return nil
}

// localENIPAddr returns the address advertised in ListIdentity.
func localENIPAddr(conn net.Conn) (net.IP, uint16) {
	ip, port := net.IPv4zero, uint16(defaultENIPPort)
	if conn == nil || conn.LocalAddr() == nil {
		return ip, port
	}
	h, p, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ip, port
	}
	if parsed := net.ParseIP(h); parsed != nil && parsed.To4() != nil {
		ip = parsed
	}
	if v, err := strconv.ParseUint(p, 10, 16); err == nil && v != 0 {
		port = uint16(v)
	}
	return ip, port
}

// respond builds the reply to one request. A nil reply means none is sent
// (NOP, UnRegisterSession); done ends the session.
func (s *enipServer) respond(hdr enip.Header, body []byte, ip net.IP, port uint16) (reply, recorded []byte, done bool) {
	switch hdr.Command {
	case enip.CmdListIdentity:
		id := enip.DefaultIdentity
		id.SerialNumber = enipSerial()
		return enip.ListIdentityReply(hdr, id, ip, port), enip.ListIdentityReply(hdr, id, scrubbedSensorIP, port), false
	case enip.CmdListServices:
		return enip.ListServicesReply(hdr), nil, false
	case enip.CmdListInterfaces:
		return enip.ListInterfacesReply(hdr), nil, false
	case enip.CmdRegisterSession:
		handle := enipSessionHandle()
		reply, ok := enip.RegisterSessionReply(hdr, body, handle)
		if ok {
			s.session = handle
		}
		return reply, nil, false
	case enip.CmdUnRegisterSession:
		return nil, nil, true
	case enip.CmdNOP:
		return nil, nil, false
	case enip.CmdSendRRData, enip.CmdSendUnitData:
		if s.session == 0 || hdr.SessionHandle != s.session {
			return enip.ErrorReply(hdr, enip.StatusInvalidSession), nil, false
		}
	}
	return enip.ErrorReply(hdr, enip.StatusInvalidCommand), nil, false
}

// HandleENIP answers EtherNet/IP encapsulation list and session commands as
// a single adapter. No CIP objects are emulated behind SendRRData.
func HandleENIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &enipServer{events: []parsedENIP{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("enip", conn, md, helpers.FirstOrEmpty[parsedENIP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "enip"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close EtherNet/IP connection", slog.String("protocol", "enip"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	logger.Info(
		"EtherNet/IP connection",
		slog.String("handler", "enip"),
		slog.String("protocol", "enip"),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
	)

	ip, localPort := localENIPAddr(conn)
	for i := 0; ; i++ {
		if i >= maxENIPRequests {
			endReason = connection.EndMaxFrames
			break
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "enip"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		hdr, body, err := server.read()
		if errors.Is(err, errENIPOversize) {
			if err := server.write(enip.ErrorReply(hdr, enip.StatusInvalidLength), nil); err != nil {
				logger.Debug("Failed to write to connection", slog.String("protocol", "enip"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
			}
			break
		}
		if err != nil {
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				endReason = connection.EndClientClose
			default:
				logger.Debug("Failed to read data", slog.String("protocol", "enip"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
			}
			break
		}
		reply, recorded, done := server.respond(hdr, body, ip, localPort)
		if reply != nil {
			if err := server.write(reply, recorded); err != nil {
				logger.Error("Failed to write to connection", slog.String("protocol", "enip"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if done {
			break
		}
	}
	return nil
}
