package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/imap"
)

const (
	// imapMaxLine caps one client line.
	imapMaxLine = 4096
	// imapMaxLiteral caps one {n} literal; logins never need more.
	imapMaxLiteral = 4096
	// imapMaxLiterals bounds the literals folded into one command.
	imapMaxLiterals = 4
	// imapMaxCommands bounds the number of client commands per session.
	imapMaxCommands = 32
)

type parsedIMAP struct {
	Direction  string `json:"direction,omitempty"`   // "read" (from attacker) or "write" (from honeypot)
	Tag        string `json:"tag,omitempty"`         // command tag on read frames
	Command    string `json:"command,omitempty"`     // upper-cased verb, "sasl-response" or "tls"
	Mechanism  string `json:"mechanism,omitempty"`   // AUTHENTICATE mechanism
	Username   string `json:"username,omitempty"`    // LOGIN user or SASL authcid
	Password   string `json:"password,omitempty"`    // LOGIN or SASL password
	ServerName string `json:"server_name,omitempty"` // SNI after STARTTLS
	Status     string `json:"status,omitempty"`      // OK, NO, BAD or "+" (continuation) on writes
	Payload    []byte `json:"payload,omitempty"`     // raw bytes as seen on the wire
	Truncated  bool   `json:"truncated,omitempty"`   // a line or literal exceeded its cap
}

type imapServer struct {
	events []parsedIMAP
	conn   net.Conn
	r      *bufio.Reader
	w      io.Writer
	tls    bool
}

func (s *imapServer) write(status string, data []byte) error {
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedIMAP{Direction: "write", Status: status, Payload: data})
	return nil
}

func (s *imapServer) reply(r imap.Reply) error {
	return s.write(r.Status, r.Data)
}

// readLine reads one line into a new read frame and returns its index.
func (s *imapServer) readLine() (int, error) {
	line, err := s.r.ReadSlice('\n')
	truncated := errors.Is(err, bufio.ErrBufferFull)
	if err != nil && !truncated {
		if len(line) > 0 {
			s.events = append(s.events, parsedIMAP{Direction: "read", Payload: append([]byte(nil), line...)})
		}
		return -1, err
	}
	s.events = append(s.events, parsedIMAP{Direction: "read", Payload: append([]byte(nil), line...), Truncated: truncated})
	return len(s.events) - 1, nil
}

// readCommand reads a command line and any literals it announces into one
// read frame. Continuation writes for synchronizing literals are recorded
// after that frame.
func (s *imapServer) readCommand() (int, error) {
	idx, err := s.readLine()
	if err != nil || s.events[idx].Truncated {
		return idx, err
	}
	last := s.events[idx].Payload
	for range imapMaxLiterals {
		n, sync, ok := imap.LiteralSize(last)
		if !ok {
			break
		}
		if n > imapMaxLiteral {
			s.events[idx].Truncated = true
			return idx, nil
		}
		if sync {
			if err := s.write("+", []byte(imap.LiteralContinue)); err != nil {
				return idx, err
			}
		}
		lit := make([]byte, n)
		if _, err := io.ReadFull(s.r, lit); err != nil {
			s.events[idx].Payload = append(s.events[idx].Payload, lit...)
			return idx, err
		}
		line, err := s.r.ReadSlice('\n')
		last = append([]byte(nil), line...)
		s.events[idx].Payload = append(append(s.events[idx].Payload, lit...), last...)
		if errors.Is(err, bufio.ErrBufferFull) {
			s.events[idx].Truncated = true
			return idx, nil
		}
		if err != nil {
			return idx, err
		}
	}
	return idx, nil
}

// saslResponse prompts for and reads one AUTHENTICATE response line.
func (s *imapServer) saslResponse(prompt string) (int, string, error) {
	if err := s.write("+", []byte(prompt)); err != nil {
		return -1, "", err
	}
	idx, err := s.readLine()
	if err != nil {
		return idx, "", err
	}
	s.events[idx].Command = "sasl-response"
	return idx, strings.TrimSpace(string(s.events[idx].Payload)), nil
}

// authenticate runs an AUTHENTICATE exchange and records the credentials on
// the frame that carried them. Every exchange fails.
func (s *imapServer) authenticate(idx int, cmd imap.Command) error {
	if len(cmd.Args) == 0 {
		return s.reply(imap.Tagged(cmd.Tag, "BAD", "Error in IMAP command AUTHENTICATE: Missing arguments."))
	}
	mech := strings.ToUpper(cmd.Args[0])
	s.events[idx].Mechanism = mech
	initial, hasInitial := "", len(cmd.Args) > 1
	if hasInitial {
		initial = cmd.Args[1]
	}
	switch mech {
	case "PLAIN":
		respIdx, resp := idx, initial
		if !hasInitial {
			var err error
			if respIdx, resp, err = s.saslResponse(imap.SASLContinue); err != nil {
				return err
			}
		}
		if resp == "*" {
			return s.reply(imap.AuthAborted(cmd.Tag))
		}
		if user, pass, err := imap.DecodePlain(resp); err == nil {
			s.events[respIdx].Username = user
			s.events[respIdx].Password = pass
		}
	case "LOGIN":
		userIdx, user := idx, initial
		if !hasInitial {
			var err error
			if userIdx, user, err = s.saslResponse(imap.LoginUserPrompt); err != nil {
				return err
			}
		}
		if user == "*" {
			return s.reply(imap.AuthAborted(cmd.Tag))
		}
		s.events[userIdx].Username, _ = imap.DecodeBase64(user)
		passIdx, pass, err := s.saslResponse(imap.LoginPassPrompt)
		if err != nil {
			return err
		}
		if pass == "*" {
			return s.reply(imap.AuthAborted(cmd.Tag))
		}
		s.events[passIdx].Password, _ = imap.DecodeBase64(pass)
	default:
		return s.reply(imap.Tagged(cmd.Tag, "NO", "Unsupported authentication mechanism."))
	}
	return s.reply(imap.AuthFailed(cmd.Tag))
}

// startTLS runs a server TLS handshake over the current reader and switches
// the transport to it. The client's handshake bytes are recorded as a frame.
func (s *imapServer) startTLS() error {
	tlsConn, info, err := helpers.TerminateTLSFrom(s.conn, s.r)
	s.events = append(s.events, parsedIMAP{
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
	s.r = bufio.NewReaderSize(tlsConn, imapMaxLine)
	s.w = tlsConn
	return nil
}

// HandleIMAP emulates a Dovecot IMAP4rev1 server that greets first and
// refuses every login. For IMAPS (tcp/993) the rule sets tls: true, so conn
// is already decrypted; on tcp/143 the client can upgrade with STARTTLS.
func HandleIMAP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &imapServer{
		events: []parsedIMAP{},
		conn:   conn,
		r:      bufio.NewReaderSize(conn, imapMaxLine),
		w:      conn,
		tls:    md.TLS != nil,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("imap", conn, md, helpers.FirstOrEmpty[parsedIMAP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "imap"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close IMAP connection", slog.String("protocol", "imap"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "imap"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	if err := server.write("OK", []byte(imap.Greeting(server.tls))); err != nil {
		logger.Debug("Failed to write greeting", slog.String("protocol", "imap"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	host, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	for range imapMaxCommands {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "imap"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		idx, err := server.readCommand()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "imap"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		frame := &server.events[idx]
		if frame.Truncated {
			endReason = connection.EndReadError
			return nil
		}
		cmd, err := imap.ParseCommand(frame.Payload)
		if err != nil {
			if err := server.reply(imap.BadCommand()); err != nil {
				endReason = connection.EndWriteError
				return nil
			}
			continue
		}
		frame.Tag = cmd.Tag
		frame.Command = cmd.Verb
		if cmd.Verb == "LOGIN" && len(cmd.Args) >= 2 {
			frame.Username = cmd.Args[0]
			frame.Password = cmd.Args[1]
		}

		logger.Info("IMAP command received",
			slog.String("handler", "imap"),
			slog.String("command", cmd.Verb),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
		)

		if cmd.Verb == "AUTHENTICATE" {
			if err := server.authenticate(idx, cmd); err != nil {
				logger.Debug("Failed AUTHENTICATE exchange", slog.String("protocol", "imap"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
			continue
		}
		resp := imap.Respond(cmd, server.tls)
		if err := server.reply(resp); err != nil {
			logger.Debug("Failed to write reply", slog.String("protocol", "imap"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if resp.Close {
			return nil
		}
		if cmd.Verb == "STARTTLS" && resp.Status == "OK" {
			if err := server.startTLS(); err != nil {
				logger.Debug("Failed STARTTLS handshake", slog.String("protocol", "imap"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
