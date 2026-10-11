package tcp

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/ident"
)

// maxIdentQueries bounds the queries answered on one connection; identd keeps
// the connection open between queries, scanners send one.
const maxIdentQueries = 4

type parsedIdent struct {
	Direction  string `json:"direction,omitempty"`   // "read" (from attacker) or "write" (from honeypot)
	Command    string `json:"command,omitempty"`     // "query" when the read line is a port pair
	ServerPort int    `json:"server_port,omitempty"` // queried port on this host
	ClientPort int    `json:"client_port,omitempty"` // queried port on the client
	Status     string `json:"status,omitempty"`      // "no-user" or "invalid-port" on writes
	Payload    []byte `json:"payload,omitempty"`     // raw bytes as seen on the wire
	Truncated  bool   `json:"truncated,omitempty"`   // the line exceeded ident.MaxLine
}

// HandleIdent takes a net.Conn and answers Identification Protocol (RFC 1413)
// queries with "ERROR : NO-USER", as identd does for a connection it does not
// own. Anything that is not a port pair is recorded and the connection closed.
func HandleIdent(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedIdent{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("ident", conn, md, helpers.FirstOrEmpty[parsedIdent](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ident"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close ident connection", slog.String("protocol", "ident"), producer.ErrAttr(err))
		}
	}()

	reader := bufio.NewReaderSize(conn, ident.MaxLine)
	for i := 0; i < maxIdentQueries; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "ident"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		line, err := reader.ReadSlice('\n')
		if len(line) == 0 {
			if err != nil {
				logger.Debug("Failed to read data", slog.String("protocol", "ident"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
			}
			return nil
		}
		// ReadSlice returns the reader's buffer; copy before storing.
		data := append([]byte(nil), line...)
		frame := parsedIdent{Direction: "read", Payload: data, Truncated: errors.Is(err, bufio.ErrBufferFull)}
		q, ok := ident.ParseQuery(data)
		if !ok || frame.Truncated {
			events = append(events, frame)
			logger.Debug("Not an ident query", slog.String("protocol", "ident"), slog.Int("bytes", len(data)))
			return nil
		}
		frame.Command, frame.ServerPort, frame.ClientPort = "query", q.ServerPort, q.ClientPort
		events = append(events, frame)

		// A query without a newline still gets an answer (the client may have
		// half-closed); the session ends after it.
		reply := ident.BuildReply(q)
		if _, werr := conn.Write(reply); werr != nil {
			logger.Debug("Failed to write response", slog.String("protocol", "ident"), producer.ErrAttr(werr))
			endReason = connection.EndWriteError
			return nil
		}
		events = append(events, parsedIdent{Direction: "write", Status: strings.ToLower(q.Error()), Payload: reply})
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "ident"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
