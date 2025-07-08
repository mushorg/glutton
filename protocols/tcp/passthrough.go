package tcp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
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

// Dial to the source ip, acting as a proxy between the client and real source by piping the data back and forth w/o interfering w it.
func HandlePassThrough(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, capture bool) error {
	var err error

	srcAddr := conn.RemoteAddr().String()
	destAddr := md.Rule.Target

	server := &passThroughServer{
		events: []parsedPassThrough{},
		conn:   conn,
		target: destAddr,
		source: srcAddr,
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

	// Source to target
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				logger.Info("source to target", slog.String("payload", string(buf[:n])))
				server.recordEvent("source->target", buf[:n], capture)
				if _, err := targetConn.Write(buf[:n]); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				logger.Info("target to source", slog.String("payload", string(buf[:n])))
				server.recordEvent("target->source", buf[:n], capture)
				if _, err := conn.Write(buf[:n]); err != nil {
					errChan <- err
					return
				}
			}

		}
	}()

	// When either of the error is returned or no more data is left to be sent, the go routines exit.
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
