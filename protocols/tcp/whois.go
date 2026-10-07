package tcp

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

// Cap the query line; real WHOIS queries are a domain, IP or handle.
const maxWhoisQuery = 512

// whoisNoMatch is a generic registry-style answer that does not echo the query.
const whoisNoMatch = "% No entries found for the selected source(s).\r\n"

type parsedWhois struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // the query on read frames, trimmed of CRLF
	Status    string `json:"status,omitempty"`    // "no-match" on the write frame
	Payload   []byte `json:"payload,omitempty"`   // raw bytes as seen on the wire
	Truncated bool   `json:"truncated,omitempty"` // the query exceeded maxWhoisQuery
}

// HandleWHOIS takes a net.Conn and answers a single WHOIS query (RFC 3912).
// The client speaks first; a client that sends nothing produces an empty event.
func HandleWHOIS(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedWhois{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("whois", conn, md, helpers.FirstOrEmpty[parsedWhois](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "whois"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close WHOIS connection", slog.String("protocol", "whois"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "whois"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	line, err := bufio.NewReader(io.LimitReader(conn, maxWhoisQuery)).ReadString('\n')
	// Keep a partial query (no newline) so scanners that skip CRLF are recorded.
	if len(line) > 0 {
		events = append(events, parsedWhois{
			Direction: "read",
			Command:   strings.TrimRight(line, "\r\n"),
			Payload:   []byte(line),
			Truncated: err != nil && len(line) >= maxWhoisQuery,
		})
		reply := []byte(whoisNoMatch)
		if _, werr := conn.Write(reply); werr != nil {
			logger.Debug("Failed to write response", slog.String("protocol", "whois"), producer.ErrAttr(werr))
			endReason = connection.EndWriteError
			return nil
		}
		events = append(events, parsedWhois{Direction: "write", Status: "no-match", Payload: reply})
		return nil
	}
	if err != nil {
		logger.Debug("Failed to read data", slog.String("protocol", "whois"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
	}
	return nil
}
