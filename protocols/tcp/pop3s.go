package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/pop3"
)

const (
	// pop3sMaxLine caps one client command line.
	pop3sMaxLine = 4096
	// pop3sMaxCommands bounds the number of client commands per session.
	pop3sMaxCommands = 32
	pop3sHost        = "mail.localdomain"
)

type parsedPOP3 struct {
	Direction string `json:"direction,omitempty"`
	// Command is the upper-cased POP3 verb on read frames, or "tls" for the
	// raw TLS ClientHello bytes.
	Command    string `json:"command,omitempty"`
	Status     string `json:"status,omitempty"`      // +OK or -ERR on write frames
	Username   string `json:"username,omitempty"`    // USER argument; PASS is never stored
	ServerName string `json:"server_name,omitempty"` // SNI from the ClientHello
	Payload    []byte `json:"payload,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// HandlePOP3S emulates a POP3S (implicit TLS, tcp/995) server. Every login fails.
func HandlePOP3S(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var events []parsedPOP3
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("pop3s", conn, md, helpers.FirstOrEmpty[parsedPOP3](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close POP3S connection", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	cert, err := helpers.SelfSignedCertificate(pkix.Name{CommonName: pop3sHost}, pop3sHost)
	if err != nil {
		endReason = connection.EndReadError
		return err
	}

	rec := &cappedRecorder{r: conn, limit: pop3sMaxLine}
	var serverName string
	tlsConn := tls.Server(&peekedConn{Conn: conn, r: rec}, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			return nil, nil
		},
	})
	hsErr := tlsConn.Handshake()
	if len(rec.buf) > 0 {
		events = append(events, parsedPOP3{
			Direction:  "read",
			Command:    "tls",
			ServerName: serverName,
			Payload:    rec.buf,
			Truncated:  rec.truncated,
		})
	}
	if hsErr != nil {
		// a scanner that connects and waits, or a client that is not speaking TLS
		logger.Debug("TLS handshake failed", slog.String("protocol", "pop3s"), producer.ErrAttr(hsErr))
		endReason = connection.EndReasonFromRead(hsErr)
		return nil
	}

	write := func(status string, data []byte) error {
		if _, err := tlsConn.Write(data); err != nil {
			return err
		}
		events = append(events, parsedPOP3{Direction: "write", Status: status, Payload: data})
		return nil
	}
	if err := write("+OK", []byte(pop3.Greeting)); err != nil {
		logger.Debug("Failed to write greeting", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	r := bufio.NewReaderSize(tlsConn, pop3sMaxLine)
	for range pop3sMaxCommands {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		line, err := r.ReadSlice('\n')
		truncated := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !truncated {
			logger.Debug("Failed to read data", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		line = append([]byte(nil), line...)
		cmd := pop3.ParseCommand(string(line))
		frame := parsedPOP3{Direction: "read", Command: cmd.Verb, Payload: line, Truncated: truncated}
		if cmd.Verb == "USER" {
			frame.Username = cmd.Arg
		}
		events = append(events, frame)
		if truncated {
			endReason = connection.EndReadError
			return nil
		}
		resp := pop3.Respond(cmd)
		if err := write(resp.Status, resp.Data); err != nil {
			logger.Debug("Failed to write reply", slog.String("protocol", "pop3s"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if resp.Close {
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
