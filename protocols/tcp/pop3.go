package tcp

import (
	"bufio"
	"context"
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
	// pop3MaxLine caps one client command line.
	pop3MaxLine = 4096
	// pop3MaxCommands bounds the number of client commands per session.
	pop3MaxCommands = 32
)

type parsedPOP3 struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`  // upper-cased POP3 verb on read frames
	Status    string `json:"status,omitempty"`   // +OK or -ERR on write frames
	Username  string `json:"username,omitempty"` // USER argument; PASS is never parsed
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// HandlePOP3 emulates a POP3 server that greets first. Every login fails.
// For POP3S (tcp/995) the rule sets tls: true, so conn is already decrypted.
func HandlePOP3(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var events []parsedPOP3
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("pop3", conn, md, helpers.FirstOrEmpty[parsedPOP3](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close POP3 connection", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		}
	}()

	write := func(status string, data []byte) error {
		if _, err := conn.Write(data); err != nil {
			return err
		}
		events = append(events, parsedPOP3{Direction: "write", Status: status, Payload: data})
		return nil
	}

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	if err := write("+OK", []byte(pop3.Greeting)); err != nil {
		logger.Debug("Failed to write greeting", slog.String("protocol", "pop3"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	r := bufio.NewReaderSize(conn, pop3MaxLine)
	for range pop3MaxCommands {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "pop3"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		line, err := r.ReadSlice('\n')
		truncated := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !truncated {
			logger.Debug("Failed to read data", slog.String("protocol", "pop3"), producer.ErrAttr(err))
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
			logger.Debug("Failed to write reply", slog.String("protocol", "pop3"), producer.ErrAttr(err))
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
