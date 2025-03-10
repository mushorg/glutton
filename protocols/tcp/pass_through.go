package tcp

import (
	"context"
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
	PayloadHash string `json:"payload_hash,omitempty"`
}

type passThroughServer struct {
	events []parsedPassThrough
	target string
}

func HandlePassThrough(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	srcAddr := conn.RemoteAddr().String()
	logger.Info("PassThrough details",
		slog.String("srcAddr", srcAddr),
		slog.String("localAddr", conn.LocalAddr().String()))

	destAddr := md.Rule.Target
	targetConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer targetConn.Close()
	defer conn.Close()

	errChan := make(chan error, 2)

	// source to target
	go func() {
		_, err := io.Copy(targetConn, conn)
		errChan <- err
	}()

	// target to source
	go func() {
		_, err := io.Copy(conn, targetConn)
		errChan <- err
	}()

	// wait for either direction to succeed
	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			logger.Error("Transfer error", producer.ErrAttr(err))
			return err
		}
	case <-ctx.Done():
		logger.Info("Context cancelled")
		return ctx.Err()
	}

	logger.Info("Pass through completed successfully")
	return nil
}
