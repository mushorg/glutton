package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/smtp"
	"github.com/spf13/viper"
)

const (
	// maxDataRead is the most DATA body lines kept in the produced event.
	maxDataRead = 500
	// maxDataBytes is the most DATA body bytes kept in the produced event.
	maxDataBytes = 256 << 10
	// maxLineBytes is the most bytes kept from a single client line.
	maxLineBytes = 1024
	// maxRecipients is the RCPT limit per transaction (RFC 5321 minimum).
	maxRecipients = 100
	// defaultSMTPHostname is announced when smtp.hostname is not configured.
	defaultSMTPHostname = "mail.localdomain"
)

const (
	replyOK         = "250 OK"
	replyUnknown    = "500 Recheck the command you entered."
	replyBadPath    = "501 Syntax error in parameters or arguments"
	replyAuthFailed = "535 5.7.8 Authentication credentials invalid"
	replyAuthCancel = "501 5.7.0 Authentication cancelled"
	replyAuthMech   = "504 5.5.4 Unrecognized authentication type"
	replyNoTLS      = "454 4.7.0 TLS not available due to temporary reason"
	replyBadSeq     = "503 5.5.1 Bad sequence of commands"
	replyNestedMail = "503 5.5.1 Error: nested MAIL command"
	replyTooMany    = "452 4.5.3 Too many recipients"
)

// smtpHostname is the server name used in the greeting and HELO/EHLO replies.
func smtpHostname() string {
	if name := viper.GetString("smtp.hostname"); name != "" {
		return name
	}
	return defaultSMTPHostname
}

// heloReply greets the client by the name it sent in HELO.
func heloReply(hostname, client string) string {
	return smtp.Reply(250, hostname+" Hello "+smtp.ClientName(client))
}

// ehloReply advertises AUTH so credential guessers keep talking. STARTTLS is
// not advertised because the handler cannot upgrade the connection.
func ehloReply(hostname, client string) string {
	return smtp.Reply(250,
		hostname+" Hello "+smtp.ClientName(client),
		"PIPELINING",
		"SIZE 10240000",
		"AUTH PLAIN LOGIN",
		"8BITMIME",
		"HELP",
	)
}

type parsedSMTP struct {
	Direction string `json:"direction,omitempty"`
	// Command is the upper-cased SMTP verb for client command lines
	// (HELO, MAIL, RCPT, DATA, QUIT, ...). It is empty for server replies.
	// AUTH continuation lines also use AUTH.
	Command string `json:"command,omitempty"`
	Status  string `json:"status,omitempty"`  // SMTP reply code on write frames
	Mailbox string `json:"mailbox,omitempty"` // MAIL FROM / RCPT TO address
	Params  string `json:"params,omitempty"`  // ESMTP parameters after the address
	// Username is the AUTH PLAIN/LOGIN identity. The password is not stored.
	Username  string `json:"username,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"` // a line or DATA cap dropped bytes
}

type smtpServer struct {
	events []parsedSMTP
	conn   net.Conn
	bufin  *bufio.Reader
	bufout *bufio.Writer
	// sleep delays replies to look less like a honeypot; tests replace it with a no-op.
	sleep    func() error
	hostname string
	// mailFrom and rcpts track the current mail transaction.
	mailFrom bool
	rcpts    int
}

func newSMTPServer(conn net.Conn) *smtpServer {
	return &smtpServer{
		events:   []parsedSMTP{},
		conn:     conn,
		bufin:    bufio.NewReader(conn),
		bufout:   bufio.NewWriter(conn),
		sleep:    randomSleep,
		hostname: smtpHostname(),
	}
}

// reset clears the current mail transaction
func (s *smtpServer) reset() {
	s.mailFrom = false
	s.rcpts = 0
}

// write sends a reply to the client and records it as a write event
func (s *smtpServer) write(msg string) error {
	line := msg + "\r\n"
	if _, err := s.bufout.WriteString(line); err != nil {
		return err
	}
	if err := s.bufout.Flush(); err != nil {
		return err
	}
	s.events = append(s.events, parsedSMTP{
		Direction: "write",
		Status:    smtp.Status(msg),
		Payload:   []byte(line),
	})
	return nil
}

// readLine reads a single line from the client without recording an event.
// At most maxLineBytes are kept; the rest of a longer line is read and
// discarded, and truncated is set.
func (s *smtpServer) readLine() (string, bool, error) {
	var line []byte
	total := 0
	for {
		chunk, err := s.bufin.ReadSlice('\n')
		total += len(chunk)
		if room := maxLineBytes - len(line); room > 0 {
			line = append(line, chunk[:min(room, len(chunk))]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return string(line), total > maxLineBytes, err
	}
}

// read reads a command line from the client and records it as a read event
func (s *smtpServer) read() (smtp.Command, error) {
	line, truncated, err := s.readLine()
	if err != nil {
		return smtp.Command{}, err
	}
	cmd := smtp.ParseCommand(line)
	s.events = append(s.events, parsedSMTP{
		Direction: "read",
		Command:   cmd.Verb,
		Mailbox:   cmd.Mailbox,
		Params:    cmd.Params,
		Payload:   []byte(line),
		Truncated: truncated,
	})
	return cmd, nil
}

// readAuth reads an AUTH continuation line and records it as an AUTH read event
func (s *smtpServer) readAuth() (string, error) {
	line, truncated, err := s.readLine()
	if err != nil {
		return "", err
	}
	s.events = append(s.events, parsedSMTP{
		Direction: "read",
		Command:   "AUTH",
		Payload:   []byte(line),
		Truncated: truncated,
	})
	return strings.TrimSpace(line), nil
}

// setUsername records an AUTH identity on the most recent read frame
func (s *smtpServer) setUsername(user string) {
	s.events[len(s.events)-1].Username = user
}

// auth runs an AUTH PLAIN or AUTH LOGIN exchange and returns the final reply.
// Every attempt fails, so each credential guess becomes its own exchange.
// The returned end reason is set when err is not nil.
func (s *smtpServer) auth(arg string) (string, string, error) {
	mech, initial, _ := strings.Cut(arg, " ")
	initial = strings.TrimSpace(initial)
	switch strings.ToUpper(mech) {
	case "PLAIN":
		if initial == "" {
			if err := s.write("334 "); err != nil {
				return "", connection.EndWriteError, err
			}
			line, err := s.readAuth()
			if err != nil {
				return "", connection.EndReasonFromRead(err), err
			}
			initial = line
		}
		if initial == "*" {
			return replyAuthCancel, "", nil
		}
		if user, ok := smtp.DecodePlain(initial); ok {
			s.setUsername(user)
		}
	case "LOGIN":
		if initial == "" {
			if err := s.write("334 VXNlcm5hbWU6"); err != nil { // "Username:"
				return "", connection.EndWriteError, err
			}
			line, err := s.readAuth()
			if err != nil {
				return "", connection.EndReasonFromRead(err), err
			}
			initial = line
		}
		if initial == "*" {
			return replyAuthCancel, "", nil
		}
		if user, ok := smtp.DecodeLogin(initial); ok {
			s.setUsername(user)
		}
		if err := s.write("334 UGFzc3dvcmQ6"); err != nil { // "Password:"
			return "", connection.EndWriteError, err
		}
		line, err := s.readAuth()
		if err != nil {
			return "", connection.EndReasonFromRead(err), err
		}
		if line == "*" {
			return replyAuthCancel, "", nil
		}
	default:
		return replyAuthMech, "", nil
	}
	return replyAuthFailed, "", nil
}

// readData reads the message body following a DATA command, up to the
// terminating "." line, and records it as a single read event. The frame keeps
// at most maxDataRead lines and maxDataBytes bytes and is marked truncated
// past either cap; the rest of the body is still read up to the terminator so
// it is never parsed as commands.
func (s *smtpServer) readData() ([]byte, error) {
	var body bytes.Buffer
	var readErr error
	truncated := false
	for lines := 0; ; lines++ {
		line, long, err := s.readLine()
		end := err == nil && !long && (line == ".\r\n" || line == ".\n")
		switch {
		case truncated:
		case end:
			body.WriteString(line)
		case lines >= maxDataRead:
			truncated = true
		default:
			room := maxDataBytes - body.Len()
			body.WriteString(line[:min(room, len(line))])
			truncated = long || len(line) > room
		}
		if err != nil {
			readErr = err
			break
		}
		if end {
			break
		}
	}
	if body.Len() > 0 || truncated {
		s.events = append(s.events, parsedSMTP{
			Direction: "read",
			Command:   "DATA",
			Payload:   body.Bytes(),
			Truncated: truncated,
		})
	}
	return body.Bytes(), readErr
}

func randomSleep() error {
	// between 0.5 - 1.5 seconds
	rtime, err := rand.Int(rand.Reader, big.NewInt(1500))
	if err != nil {
		return err
	}
	duration := time.Duration(rtime.Int64()+500) * time.Millisecond
	time.Sleep(duration)
	return nil
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func HandleSMTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleSMTP(ctx, newSMTPServer(conn), md, logger, h)
}

func handleSMTP(ctx context.Context, server *smtpServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("smtp", conn, md, helpers.FirstOrEmpty[parsedSMTP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "smtp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SMTP connection", slog.String("protocol", "smtp"), producer.ErrAttr(err))
		}
	}()

	if err := server.sleep(); err != nil {
		return err
	}
	if err := server.write("220 " + server.hostname + " ESMTP ready"); err != nil {
		endReason = connection.EndWriteError
		return err
	}

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smtp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		cmd, err := server.read()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smtp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
		logger.Debug("SMTP Query", slog.String("command", cmd.Verb), slog.String("arg", cmd.Arg), slog.String("protocol", "smtp"))

		var resp string
		switch cmd.Verb {
		case "HELO", "EHLO":
			if cmd.Arg == "" {
				resp = "501 Syntax: " + cmd.Verb + " hostname"
				break
			}
			server.reset()
			resp = heloReply(server.hostname, cmd.Arg)
			if cmd.Verb == "EHLO" {
				resp = ehloReply(server.hostname, cmd.Arg)
			}
		case "MAIL":
			switch {
			case server.mailFrom:
				resp = replyNestedMail
			case !cmd.ValidPath():
				resp = replyBadPath
			default:
				server.mailFrom = true
				resp = replyOK
			}
		case "RCPT":
			switch {
			case !server.mailFrom:
				resp = replyBadSeq
			case !cmd.ValidPath():
				resp = replyBadPath
			case server.rcpts >= maxRecipients:
				resp = replyTooMany
			default:
				server.rcpts++
				resp = replyOK
			}
		case "DATA":
			if server.rcpts == 0 {
				resp = replyBadSeq
				break
			}
			if err := server.write("354 End data with <CRLF>.<CRLF>"); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			body, err := server.readData()
			logger.Debug("SMTP Data", slog.String("data", string(body)), slog.String("protocol", "smtp"))
			if err != nil {
				logger.Debug("Failed to read data", slog.String("protocol", "smtp"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
			if err := server.sleep(); err != nil {
				return err
			}
			server.reset()
			resp = replyOK
		case "RSET":
			server.reset()
			resp = replyOK
		case "NOOP":
			resp = replyOK
		case "AUTH":
			reply, reason, err := server.auth(cmd.Arg)
			if err != nil {
				endReason = reason
				if reason == connection.EndWriteError {
					return err
				}
				logger.Debug("Failed to read AUTH data", slog.String("protocol", "smtp"), producer.ErrAttr(err))
				return nil
			}
			if err := server.sleep(); err != nil {
				return err
			}
			resp = reply
		case "STARTTLS":
			resp = replyNoTLS
		case "QUIT":
			if err := server.write("221 Bye"); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			return nil
		default:
			resp = replyUnknown
		}
		if err := server.write(resp); err != nil {
			endReason = connection.EndWriteError
			return err
		}
	}
	return nil
}
