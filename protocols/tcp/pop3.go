package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/pop3"
)

const (
	// pop3MaxLine caps one client command line.
	pop3MaxLine = 4096
	// pop3MaxCommands bounds the number of client commands per session.
	pop3MaxCommands = 32
)

type parsedPOP3 struct {
	Direction  string `json:"direction,omitempty"`
	Command    string `json:"command,omitempty"`     // upper-cased POP3 verb, or "tls" for a handshake
	Status     string `json:"status,omitempty"`      // +OK or -ERR on write frames
	Username   string `json:"username,omitempty"`    // USER argument, or APOP name
	Password   string `json:"password,omitempty"`    // PASS argument
	Digest     string `json:"digest,omitempty"`      // APOP MD5 digest
	ServerName string `json:"server_name,omitempty"` // SNI of an in-handler TLS handshake
	Payload    []byte `json:"payload,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type pop3Server struct {
	events []parsedPOP3
	conn   net.Conn
	r      *bufio.Reader
	w      io.Writer
	tls    bool
}

func (s *pop3Server) write(status string, data []byte) error {
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedPOP3{Direction: "write", Status: status, Payload: data})
	return nil
}

// tlsNext reports whether the next client bytes open a TLS handshake record.
func (s *pop3Server) tlsNext() (bool, error) {
	first, err := s.r.Peek(1)
	if err != nil {
		return false, err
	}
	if first[0] != 0x16 {
		return false, nil
	}
	hdr, _ := s.r.Peek(3)
	return helpers.LooksLikeTLSHandshakeRecord(hdr), nil
}

// startTLS runs a server TLS handshake over the current reader and switches
// the transport to it. The client's handshake bytes are recorded as a frame
// and the TLS details go on md for the produced event.
func (s *pop3Server) startTLS(md *connection.Metadata) error {
	tlsConn, info, err := helpers.TerminateTLSFrom(s.conn, s.r)
	md.TLS = info
	md.AddInner("tls")
	s.events = append(s.events, parsedPOP3{
		Direction:  "read",
		Command:    "tls",
		ServerName: info.ServerName,
		Payload:    info.Hello,
		Truncated:  info.Truncated,
	})
	if err != nil {
		return err
	}
	s.tls = true
	s.r = bufio.NewReaderSize(tlsConn, pop3MaxLine)
	s.w = tlsConn
	return nil
}

// HandlePOP3 emulates a POP3 server that greets first. Every login fails.
// For POP3S (tcp/995) the rule sets tls: true, so conn is already decrypted.
// On tcp/110 the client can upgrade with STLS, and a client that sends a
// ClientHello instead of a command (implicit TLS on the plaintext port) gets
// a TLS handshake followed by the greeting again.
func HandlePOP3(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &pop3Server{
		events: []parsedPOP3{},
		conn:   conn,
		r:      bufio.NewReaderSize(conn, pop3MaxLine),
		w:      conn,
		tls:    md.TLS != nil,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("pop3", conn, md, helpers.FirstOrEmpty[parsedPOP3](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close POP3 connection", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	if err := server.write("+OK", []byte(pop3.Greeting)); err != nil {
		logger.Debug("Failed to write greeting", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	for range pop3MaxCommands {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		if !server.tls {
			isTLS, err := server.tlsNext()
			if err != nil {
				logger.Debug("Failed to read data", slog.String("protocol", "pop3"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
			if isTLS {
				if err := server.startTLS(&md); err != nil {
					logger.Debug("Failed TLS handshake", slog.String("protocol", "pop3"), producer.ErrAttr(err))
					endReason = connection.EndReasonFromRead(err)
					return nil
				}
				if err := server.write("+OK", []byte(pop3.Greeting)); err != nil {
					logger.Debug("Failed to write greeting", slog.String("protocol", "pop3"), producer.ErrAttr(err))
					endReason = connection.EndWriteError
					return nil
				}
				continue
			}
		}
		line, err := server.r.ReadSlice('\n')
		truncated := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !truncated {
			logger.Debug("Failed to read data", slog.String("protocol", "pop3"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		line = append([]byte(nil), line...)
		cmd := pop3.ParseCommand(string(line))
		frame := parsedPOP3{Direction: "read", Command: cmd.Verb, Payload: line, Truncated: truncated}
		switch cmd.Verb {
		case "USER":
			frame.Username = cmd.Arg
		case "PASS":
			frame.Password = cmd.Arg
		case "APOP":
			name, digest, _ := strings.Cut(cmd.Arg, " ")
			frame.Username = name
			frame.Digest = strings.TrimSpace(digest)
		}
		server.events = append(server.events, frame)
		if truncated {
			endReason = connection.EndReadError
			return nil
		}
		resp := pop3.Respond(cmd, server.tls)
		if err := server.write(resp.Status, resp.Data); err != nil {
			logger.Debug("Failed to write reply", slog.String("protocol", "pop3"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if resp.Close {
			return nil
		}
		if cmd.Verb == "STLS" && resp.Status == "+OK" {
			if err := server.startTLS(&md); err != nil {
				logger.Debug("Failed STLS handshake", slog.String("protocol", "pop3"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
