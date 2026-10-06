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
)

// maximum lines that can be read after the "DATA" command
const maxDataRead = 500

const (
	replyOK         = "250 OK"
	replyUnknown    = "500 Recheck the command you entered."
	replyBadPath    = "501 Syntax error in parameters or arguments"
	replyAuthFailed = "535 5.7.8 Authentication credentials invalid"
	replyAuthCancel = "501 5.7.0 Authentication cancelled"
	replyAuthMech   = "504 5.5.4 Unrecognized authentication type"
	replyNoTLS      = "454 4.7.0 TLS not available due to temporary reason"
)

// ehloReply advertises AUTH so credential guessers keep talking. STARTTLS is
// not advertised because the handler cannot upgrade the connection.
var ehloReply = smtp.Reply(250,
	"Hello! Pleased to meet you.",
	"PIPELINING",
	"SIZE 10240000",
	"AUTH PLAIN LOGIN",
	"8BITMIME",
	"HELP",
)

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
	Username string `json:"username,omitempty"`
	Payload  []byte `json:"payload,omitempty"`
}

type smtpServer struct {
	events []parsedSMTP
	conn   net.Conn
	bufin  *bufio.Reader
	bufout *bufio.Writer
	// sleep delays replies to look less like a honeypot; tests replace it with a no-op.
	sleep func() error
}

func newSMTPServer(conn net.Conn) *smtpServer {
	return &smtpServer{
		events: []parsedSMTP{},
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
		sleep:  randomSleep,
	}
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

// readLine reads a single line from the client without recording an event
func (s *smtpServer) readLine() (string, error) {
	return s.bufin.ReadString('\n')
}

// read reads a command line from the client and records it as a read event
func (s *smtpServer) read() (smtp.Command, error) {
	line, err := s.readLine()
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
	})
	return cmd, nil
}

// readAuth reads an AUTH continuation line and records it as an AUTH read event
func (s *smtpServer) readAuth() (string, error) {
	line, err := s.readLine()
	if err != nil {
		return "", err
	}
	s.events = append(s.events, parsedSMTP{
		Direction: "read",
		Command:   "AUTH",
		Payload:   []byte(line),
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
// terminating "." line or maxDataRead lines, and records it as a single read event
func (s *smtpServer) readData() ([]byte, error) {
	var body bytes.Buffer
	var readErr error
	for readctr := maxDataRead; readctr >= 0; readctr-- {
		line, err := s.readLine()
		body.WriteString(line)
		if err != nil {
			readErr = err
			break
		}
		// exit condition
		if line == ".\r\n" || line == ".\n" {
			break
		}
	}
	if body.Len() > 0 {
		s.events = append(s.events, parsedSMTP{
			Direction: "read",
			Command:   "DATA",
			Payload:   body.Bytes(),
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
	if err := server.write("220 Welcome!"); err != nil {
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
			if err := server.sleep(); err != nil {
				return err
			}
			resp = "250 Hello! Pleased to meet you."
			if cmd.Verb == "EHLO" {
				resp = ehloReply
			}
		case "MAIL", "RCPT":
			if !cmd.ValidPath() {
				resp = replyBadPath
				break
			}
			if err := server.sleep(); err != nil {
				return err
			}
			resp = replyOK
		case "DATA":
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
			resp = replyOK
		case "RSET", "NOOP":
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
