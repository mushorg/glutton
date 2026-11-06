package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/slp"
)

const (
	maxSLPMessage  = 4096
	maxSLPMessages = 32
)

type parsedSLP struct {
	Direction   string `json:"direction,omitempty"`    // "read" (from attacker) or "write" (from honeypot)
	Command     string `json:"command,omitempty"`      // SrvRqst, DAAdvert, ...; "malformed" when not SLPv2
	XID         string `json:"xid,omitempty"`          // hex transaction ID, e.g. 0xc0e8
	Lang        string `json:"lang,omitempty"`         // language tag
	ServiceType string `json:"service_type,omitempty"` // SrvRqst/SrvTypeRqst service type or naming authority
	Scope       string `json:"scope,omitempty"`        // scope list
	Predicate   string `json:"predicate,omitempty"`    // LDAPv3 search filter of a SrvRqst
	URL         string `json:"url,omitempty"`          // AttrRqst URL or service type, DAAdvert DA URL
	Status      string `json:"status,omitempty"`       // write error code name, e.g. SCOPE_NOT_SUPPORTED
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

type slpServer struct {
	events []parsedSLP
	conn   net.Conn
}

// errSLPFramed marks a read that was recorded but cannot continue the session.
var errSLPFramed = errors.New("slp: unframeable message")

// read reads one length-prefixed SLPv2 message. Partial or unframeable input
// is recorded as a truncated read frame before the error is returned.
func (s *slpServer) read() ([]byte, error) {
	prefix := make([]byte, slp.PrefixLen)
	n, err := io.ReadFull(s.conn, prefix)
	if err != nil {
		if n > 0 {
			s.events = append(s.events, parsedSLP{Direction: "read", Command: "malformed", Payload: prefix[:n], Truncated: true})
		}
		return nil, err
	}
	length, err := slp.MessageLength(prefix, maxSLPMessage)
	if err != nil {
		cmd := "malformed"
		if !errors.Is(err, slp.ErrVersion) {
			cmd = slp.FunctionName(prefix[1])
		}
		s.events = append(s.events, parsedSLP{Direction: "read", Command: cmd, Payload: prefix, Truncated: true})
		return nil, fmt.Errorf("%w: %w", errSLPFramed, err)
	}
	msg := make([]byte, length)
	copy(msg, prefix)
	n, err = io.ReadFull(s.conn, msg[slp.PrefixLen:])
	if err != nil {
		s.events = append(s.events, parsedSLP{Direction: "read", Command: slp.FunctionName(prefix[1]), Payload: msg[:slp.PrefixLen+n], Truncated: true})
		return nil, err
	}
	return msg, nil
}

func (s *slpServer) write(data []byte, frame parsedSLP) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

// HandleSLP speaks SLPv2 (RFC 2608) over TCP. SrvRqst, SrvTypeRqst and
// AttrRqst get the same empty reply as the UDP handler (SCOPE_NOT_SUPPORTED
// unless the scope list names "default"); DAAdverts, registrations and other
// functions are recorded without a reply, as an SA/DA would.
func HandleSLP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &slpServer{events: []parsedSLP{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("slp", conn, md, helpers.FirstOrEmpty[parsedSLP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "slp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SLP connection", slog.String("protocol", "slp"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxSLPMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "slp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		data, err := server.read()
		if err != nil {
			logger.Debug("Failed to read SLP message", slog.String("protocol", "slp"), producer.ErrAttr(err))
			if !errors.Is(err, errSLPFramed) {
				endReason = connection.EndReasonFromRead(err)
			}
			return nil
		}

		frame := parsedSLP{Direction: "read", Payload: data}
		hdr, err := slp.ParseHeader(data)
		frame.Command = slp.FunctionName(hdr.Function)
		frame.XID = fmt.Sprintf("0x%04x", hdr.XID)
		frame.Lang = hdr.Lang
		if err != nil {
			// the language tag runs past the message
			frame.Truncated = true
			server.events = append(server.events, frame)
			logger.Debug("Failed to parse SLP header", slog.String("protocol", "slp"), producer.ErrAttr(err))
			continue
		}
		req, perr := slp.ParseRequest(data, hdr)
		frame.ServiceType, frame.Scope, frame.Predicate, frame.URL = req.ServiceType, req.Scope, req.Predicate, req.URL
		frame.Truncated = perr != nil
		server.events = append(server.events, frame)

		logger.Info("SLP request received",
			slog.String("handler", "slp"),
			slog.String("protocol", "slp"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("command", frame.Command),
		)
		if perr != nil {
			logger.Debug("Failed to parse SLP body", slog.String("protocol", "slp"), producer.ErrAttr(perr))
			continue
		}

		resp, code := slp.Reply(hdr, req)
		if resp == nil {
			continue
		}
		if err := server.write(resp, parsedSLP{
			Command: slp.FunctionName(resp[1]),
			XID:     frame.XID,
			Lang:    hdr.Lang,
			Status:  slp.ErrorName(code),
		}); err != nil {
			logger.Error("Failed to write SLP reply", slog.String("protocol", "slp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
