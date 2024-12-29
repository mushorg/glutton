package tcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

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

// HandleADB Android Debug bridge handler
func HandleADB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close ADB connection", slog.String("handler", "adb"), producer.ErrAttr(err))
		}
	}()
	length, err := readHexLength(conn)
	if err != nil {
		return err
	}
	data := make([]byte, length)
	n, err := io.ReadFull(conn, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("error reading message data: %w", err)
	} else if err == io.ErrUnexpectedEOF {
		return fmt.Errorf("incomplete message data: got %d, want %d. Error: %w", n, length, err)
	}

	if err = h.ProduceTCP("adb", conn, md, data, nil); err != nil {
		logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "adb"))
	}

	logger.Info("handled adb request", slog.Int("data_read", n))
	return nil
}
