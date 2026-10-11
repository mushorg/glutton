package tcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/acpp"
)

// maxACPPMessages bounds the requests answered on one connection.
const maxACPPMessages = 8

var acppStatusNames = map[int32]string{
	acpp.ErrChecksum:       "checksum",
	acpp.ErrVersion:        "version",
	acpp.ErrUnsupported:    "unsupported",
	acpp.ErrAuthentication: "authentication",
}

type parsedACPP struct {
	Direction   string `json:"direction,omitempty"`    // "read" (from attacker) or "write" (from honeypot)
	Command     string `json:"command,omitempty"`      // ACP command name (getprop, auth, ...) or "unknown"
	Version     string `json:"version,omitempty"`      // header version, hex
	Flags       uint32 `json:"flags,omitempty"`        // header flags
	BodySize    int32  `json:"body_size,omitempty"`    // declared body size, -1 for a stream header
	BadChecksum bool   `json:"bad_checksum,omitempty"` // header checksum did not match
	Key         string `json:"key,omitempty"`          // XOR-encoded password field, hex; omitted when all zero
	Status      string `json:"status,omitempty"`       // reply error name on writes
	ErrorCode   int32  `json:"error_code,omitempty"`   // reply error code on writes
	Payload     []byte `json:"payload,omitempty"`      // raw bytes as seen on the wire
	Truncated   bool   `json:"truncated,omitempty"`    // body exceeded acpp.MaxBody
}

// HandleACPP takes a net.Conn and answers Apple AirPort Admin (ACP) requests
// like a base station that rejects them: malformed headers get a version or
// checksum error, unknown commands kUnsupportedErr, and every known command an
// authentication error. Nothing is ever authenticated.
func HandleACPP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedACPP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("acpp", conn, md, helpers.FirstOrEmpty[parsedACPP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "acpp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close ACPP connection", slog.String("protocol", "acpp"), producer.ErrAttr(err))
		}
	}()

	host, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	for i := 0; i < maxACPPMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "acpp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		raw := make([]byte, acpp.HeaderSize)
		n, err := io.ReadFull(conn, raw)
		if err != nil {
			if n > 0 {
				events = append(events, parsedACPP{Direction: "read", Payload: raw[:n]})
			}
			logger.Debug("Failed to read data", slog.String("protocol", "acpp"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		hdr, err := acpp.ParseHeader(raw)
		if err != nil {
			events = append(events, parsedACPP{Direction: "read", Payload: raw})
			logger.Debug("Not an ACPP header", slog.String("protocol", "acpp"), producer.ErrAttr(err))
			return nil
		}

		frame := parsedACPP{
			Direction: "read",
			Command:   acpp.CommandName(hdr.Command),
			Version:   fmt.Sprintf("0x%08x", hdr.Version),
			Flags:     hdr.Flags,
			BodySize:  hdr.BodySize,
		}
		if hdr.Key != [32]byte{} {
			frame.Key = hex.EncodeToString(hdr.Key[:])
		}
		code := acpp.Validate(hdr, raw)
		frame.BadChecksum = code == acpp.ErrChecksum

		// Read a declared body only from a valid header; a broken one
		// cannot be trusted to frame the stream.
		var bodyErr error
		if code == 0 && hdr.BodySize > 0 {
			want := int64(hdr.BodySize)
			frame.Truncated = want > acpp.MaxBody
			var body bytes.Buffer
			_, bodyErr = io.CopyN(&body, conn, min(want, acpp.MaxBody))
			raw = append(raw, body.Bytes()...)
		}
		frame.Payload = raw
		events = append(events, frame)
		if bodyErr != nil {
			logger.Debug("Failed to read body", slog.String("protocol", "acpp"), producer.ErrAttr(bodyErr))
			endReason = connection.EndReasonFromRead(bodyErr)
			return nil
		}

		logger.Info("ACPP request received",
			slog.String("handler", "acpp"),
			slog.String("command", frame.Command),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
		)

		if code == 0 {
			code = acpp.ErrAuthentication
		}
		reply := acpp.BuildReply(hdr.Command, code)
		if _, err := conn.Write(reply); err != nil {
			logger.Debug("Failed to write response", slog.String("protocol", "acpp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		events = append(events, parsedACPP{
			Direction: "write",
			Command:   frame.Command,
			Status:    acppStatusNames[code],
			ErrorCode: code,
			Payload:   reply,
		})
		if frame.Truncated {
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
