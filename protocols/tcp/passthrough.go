package tcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

type parsedPassThrough struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"` // Used for easier identification, can remove
}

type passThroughServer struct {
	events []parsedPassThrough
	conn   net.Conn
	target string
	source string
}

// checks whether the payload can be converted to text, to prevent expensive hex coding.
func (srv *passThroughServer) isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return (printable*100)/len(data) > 80 // threshold value --> 80%
}

// logs the payload hex or payload text.
func (srv *passThroughServer) logPayload(direction string, data []byte, logger interfaces.Logger) {
	if len(data) == 0 {
		return
	}

	fields := []any{
		slog.String("direction", direction),
		slog.Int("length", len(data)),
		slog.String("sha256", fmt.Sprintf("%x", sha256.Sum256(data))),
	}

	if srv.isLikelyText(data) {
		fields = append(fields, slog.String("payload", string(data)))
	} else {
		fields = append(fields, slog.String("hex", hex.EncodeToString(data)))
	}

	logger.Info("payload_transferred", fields...)
}

// records the events in the server
func (srv *passThroughServer) recordEvent(dir string, buf []byte, capture bool) {
	if !capture {
		return
	}
	hash := sha256.Sum256(buf)

	payload := append([]byte(nil), buf...) // defensive copy

	srv.events = append(srv.events, parsedPassThrough{
		Direction:   dir,
		Payload:     payload,
		PayloadHash: fmt.Sprintf("%x", hash[:]),
	})
}

// pipeBidirectional handles data transfer between the two connections
func pipeBidirectional(ctx context.Context, src, dst net.Conn, server *passThroughServer, logger interfaces.Logger, capture bool, errChan chan error) {
	buf := make([]byte, 4096)
	direction := getDirection(src, dst)
	for {
		select {
		case <-ctx.Done():
			errChan <- ctx.Err()
			return
		default:
			n, err := src.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			if n > 0 {
				server.logPayload(direction, buf[:n], logger)
				server.recordEvent(direction, buf[:n], capture)

				if _, err := dst.Write(buf[:n]); err != nil {
					errChan <- err
					return
				}
			}
		}
	}
}

// getDirection returns the direction as a string
func getDirection(src, dst net.Conn) string {
	srcAddr := src.RemoteAddr().String()
	dstAddr := dst.RemoteAddr().String()
	return fmt.Sprintf("%s -> %s", srcAddr, dstAddr)
}

// Dial to the source ip, acting as a proxy between the client and real source by piping the data back and forth w/o interfering w it.
func HandlePassThrough(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error

	srcAddr := conn.RemoteAddr().String()
	destAddr := md.Rule.Target

	server := &passThroughServer{
		events: []parsedPassThrough{},
		conn:   conn,
		target: destAddr,
		source: srcAddr,
	}

	var capture bool
	if viper.GetBool("capture_traffic.enabled") {
		capture = true
	}

	defer func() {
		var events []parsedPassThrough
		if capture {
			events = server.events
		}
		if err := h.ProduceTCP("passthrough", conn, md, nil, events); err != nil {
			logger.Error("failed to produce passthrough message", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close incoming connection", slog.String("handler", "passthrough"), producer.ErrAttr(err))
		}
	}()

	if destAddr == "" {
		logger.Error("no target defined", slog.String("handler", "passthrough"))
		return nil
	}

	targetConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		logger.Error("failed to connect to the target", slog.String("handler", "passthrough"), slog.String("target", string(destAddr)), producer.ErrAttr(err))
		return nil
	}
	defer targetConn.Close()

	logger.Info("starting passthrough", slog.String("source", srcAddr), slog.String("target", string(destAddr)), slog.String("handler", "passthrough"))

	errChan := make(chan error, 2)

	go pipeBidirectional(ctx, conn, targetConn, server, logger, capture, errChan) // source to target
	go pipeBidirectional(ctx, targetConn, conn, server, logger, capture, errChan) // target to source

	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			logger.Error("transfer error", producer.ErrAttr(err))
			return err
		}
	case <-ctx.Done():
		logger.Info("context cancelled")
		return ctx.Err()
	}

	logger.Info("Passthrough completed successfully")
	return nil
}
