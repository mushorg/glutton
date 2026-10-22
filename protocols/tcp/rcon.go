package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rcon"
)

// maxRCONPackets bounds the packets read on one connection.
const maxRCONPackets = 16

type parsedRCON struct {
	Direction    string `json:"direction,omitempty"`     // "read" (from attacker) or "write" (from honeypot)
	Command      string `json:"command,omitempty"`       // auth, exec, response or unknown
	RequestID    *int32 `json:"request_id,omitempty"`    // packet id; -1 on a failed AUTH_RESPONSE
	Size         int32  `json:"size,omitempty"`          // declared size field
	SizeMismatch bool   `json:"size_mismatch,omitempty"` // size field disagrees with the bytes framed by the NULs
	Password     string `json:"password,omitempty"`      // body of an auth packet
	Body         string `json:"body,omitempty"`          // body of any other packet (the console command for exec)
	Status       string `json:"status,omitempty"`        // auth-failed on writes
	Payload      []byte `json:"payload,omitempty"`       // raw bytes as seen on the wire
	Truncated    bool   `json:"truncated,omitempty"`     // body exceeded rcon.MaxBody
}

// readRCONBody reads a NUL-terminated body and, when it is already buffered,
// the trailing empty string. Bodies are framed by their NULs rather than the
// size field, which some scanners get wrong.
func readRCONBody(r *bufio.Reader) (body, raw []byte, truncated bool, err error) {
	for len(body) < rcon.MaxBody {
		b, err := r.ReadByte()
		if err != nil {
			return body, body, false, err
		}
		if b == 0 {
			raw = append(body, 0)
			if r.Buffered() > 0 {
				if next, _ := r.Peek(1); next[0] == 0 {
					_, _ = r.ReadByte()
					raw = append(raw, 0)
				}
			}
			return body, raw, false, nil
		}
		body = append(body, b)
	}
	return body, body, true, nil
}

// HandleRCON takes a net.Conn and answers Source RCON (srcds) logins like a
// game server with a different rcon_password: every SERVERDATA_AUTH gets an
// empty RESPONSE_VALUE and an AUTH_RESPONSE with id -1. An EXECCOMMAND is
// recorded and the connection closed, since it can never be authenticated.
func HandleRCON(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedRCON{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rcon", conn, md, helpers.FirstOrEmpty[parsedRCON](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rcon"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RCON connection", slog.String("protocol", "rcon"), producer.ErrAttr(err))
		}
	}()

	host, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	reader := bufio.NewReader(conn)
	for i := 0; i < maxRCONPackets; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rcon"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		raw := make([]byte, rcon.HeaderSize)
		n, err := io.ReadFull(reader, raw)
		if err != nil {
			if n > 0 {
				events = append(events, parsedRCON{Direction: "read", Payload: raw[:n]})
			}
			logger.Debug("Failed to read data", slog.String("protocol", "rcon"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		hdr, err := rcon.ParseHeader(raw)
		if err != nil {
			events = append(events, parsedRCON{Direction: "read", Payload: raw})
			logger.Debug("Not an RCON packet", slog.String("protocol", "rcon"), producer.ErrAttr(err))
			return nil
		}

		body, bodyRaw, truncated, bodyErr := readRCONBody(reader)
		frame := parsedRCON{
			Direction: "read",
			Command:   rcon.CommandName(hdr.Type),
			RequestID: &hdr.ID,
			Size:      hdr.Size,
			Payload:   append(raw, bodyRaw...),
			Truncated: truncated,
		}
		frame.SizeMismatch = bodyErr == nil && !truncated && int(hdr.Size) != len(frame.Payload)-4
		if hdr.Type == rcon.TypeAuth {
			frame.Password = string(body)
		} else {
			frame.Body = string(body)
		}
		events = append(events, frame)
		if bodyErr != nil {
			logger.Debug("Failed to read body", slog.String("protocol", "rcon"), producer.ErrAttr(bodyErr))
			endReason = connection.EndReasonFromRead(bodyErr)
			return nil
		}

		logger.Info("RCON packet received",
			slog.String("handler", "rcon"),
			slog.String("command", frame.Command),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
		)

		if truncated {
			return nil
		}
		switch hdr.Type {
		case rcon.TypeAuth:
			reply := rcon.BuildAuthFailure(hdr.ID)
			if _, err := conn.Write(reply); err != nil {
				logger.Debug("Failed to write response", slog.String("protocol", "rcon"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
			failedID := rcon.AuthFailedID
			events = append(events, parsedRCON{
				Direction: "write",
				Command:   "auth",
				RequestID: &failedID,
				Status:    "auth-failed",
				Payload:   reply,
			})
		case rcon.TypeExecCommand:
			// Nothing is ever authenticated, so a command ends the
			// session instead of getting console output.
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
