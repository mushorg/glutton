package tcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type parsedADB struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// readHexLength reads the next 4 bytes from r as an ASCII hex-encoded length and parses them into an int.
func readHexLength(r io.Reader) (int, error) {
	lengthHex := make([]byte, 4)
	_, err := io.ReadFull(r, lengthHex)
	if err != nil {
		return 0, err
	}

	length, err := strconv.ParseInt(string(lengthHex), 16, 64)
	if err != nil {
		return 0, err
	}
	// Clip the length to 255, as per the Google implementation.
	if length > 255 {
		length = 255
	}

	return int(length), nil
}

func adbCommand(data []byte) string {
	s := string(data)
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i]
	}
	if i := strings.IndexByte(s, '\x00'); i > 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

// HandleADB Android Debug bridge handler
func HandleADB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedADB{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("adb", conn, md, helpers.FirstOrEmpty[parsedADB](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "adb"))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close ADB connection", slog.String("handler", "adb"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("handler", "adb"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	length, err := readHexLength(conn)
	if err != nil {
		endReason = connection.EndReasonFromRead(err)
		return err
	}
	data := make([]byte, length)
	n, err := io.ReadFull(conn, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		endReason = connection.EndReasonFromRead(err)
		return fmt.Errorf("error reading message data: %w", err)
	} else if err == io.ErrUnexpectedEOF {
		endReason = connection.EndReasonFromRead(err)
		return fmt.Errorf("incomplete message data: got %d, want %d. Error: %w", n, length, err)
	}

	events = append(events, parsedADB{
		Direction: "read",
		Command:   adbCommand(data[:n]),
		Payload:   data[:n],
		Truncated: length == 255,
	})

	logger.Info("handled adb request", slog.Int("data_read", n))
	return nil
}
