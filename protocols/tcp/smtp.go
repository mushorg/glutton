package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

// maximum lines that can be read after the "DATA" command
const maxDataRead = 500

type parsedSMTP struct {
	Direction string `json:"direction,omitempty"`
	// Command is the upper-cased SMTP verb for client command lines
	// (HELO, MAIL, RCPT, DATA, QUIT, ...). It is empty for server replies.
	Command string `json:"command,omitempty"`
	Payload []byte `json:"payload,omitempty"`
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

// write sends a reply line to the client and records it as a write event
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
		Payload:   []byte(line),
	})
	return nil
}

// readLine reads a single line from the client without recording an event
func (s *smtpServer) readLine() (string, error) {
	return s.bufin.ReadString('\n')
}

// read reads a command line from the client and records it as a read event
func (s *smtpServer) read() (string, error) {
	line, err := s.readLine()
	if err != nil {
		return line, err
	}
	s.events = append(s.events, parsedSMTP{
		Direction: "read",
		Command:   smtpVerb(line),
		Payload:   []byte(line),
	})
	return line, nil
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

// smtpVerb extracts the upper-cased SMTP command verb from a command line
func smtpVerb(line string) string {
	line = strings.Trim(line, "\r\n")
	if line == "" {
		return ""
	}
	verb := line
	if idx := strings.IndexAny(line, " :"); idx >= 0 {
		verb = line[:idx]
	}
	return strings.ToUpper(verb)
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
func validateMail(query string) bool {
	email := regexp.MustCompile("^MAIL FROM:<.+@.+>$") // naive regex
	return email.MatchString(query)
}
func validateRCPT(query string) bool {
	rcpt := regexp.MustCompile("^RCPT TO:<.+@.+>$")
	return rcpt.MatchString(query)
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func HandleSMTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleSMTP(ctx, newSMTPServer(conn), md, logger, h)
}

func handleSMTP(ctx context.Context, server *smtpServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	defer func() {
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
		return err
	}

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smtp"), producer.ErrAttr(err))
			return nil
		}
		data, err := server.read()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smtp"), producer.ErrAttr(err))
			break
		}
		query := strings.Trim(data, "\r\n")
		logger.Debug("SMTP Query", slog.String("query", query), slog.String("protocol", "smtp"))

		var resp string
		switch {
		case strings.HasPrefix(query, "HELO "):
			if err := server.sleep(); err != nil {
				return err
			}
			resp = "250 Hello! Pleased to meet you."
		case validateMail(query):
			if err := server.sleep(); err != nil {
				return err
			}
			resp = "250 OK"
		case validateRCPT(query):
			if err := server.sleep(); err != nil {
				return err
			}
			resp = "250 OK"
		case query == "DATA":
			if err := server.write("354 End data with <CRLF>.<CRLF>"); err != nil {
				return err
			}
			body, err := server.readData()
			logger.Debug("SMTP Data", slog.String("data", string(body)), slog.String("protocol", "smtp"))
			if err != nil {
				logger.Debug("Failed to read data", slog.String("protocol", "smtp"), producer.ErrAttr(err))
				return nil
			}
			if err := server.sleep(); err != nil {
				return err
			}
			resp = "250 OK"
		case query == "QUIT":
			if err := server.write("221 Bye"); err != nil {
				return err
			}
			return nil
		default:
			resp = "500 Recheck the command you entered."
		}
		if err := server.write(resp); err != nil {
			return err
		}
	}
	return nil
}
