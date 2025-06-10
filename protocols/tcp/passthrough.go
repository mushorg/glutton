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

// Dial to the source ip, acting as a proxy between the client and real source by piping the data back and forth w/o interfering w it.
func HandlePassThrough(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	defer func() {
		if err := h.ProduceTCP("passthrough", conn, md, nil, nil); err != nil {
			logger.Error("failed to produce passthrough message", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close incoming connection", slog.String("handler", "passthrough"), producer.ErrAttr(err))
		}
	}()

	srcAddr := conn.RemoteAddr().String()

	// Still figuring out on this.
	// targetIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
	// targetPort := md.TargetPort
	// destAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)

	// Hardcoded for now
	destAddr := "127.0.0.1:5000"

	fmt.Println("dst", destAddr, " src", srcAddr)
	if destAddr == "" {
		logger.Error("no target defined", slog.String("handler", "passthrough"))
		return nil
	}

	targetConn, err := net.Dial("tcp", string(destAddr))
	if err != nil {
		logger.Error("failed to connect to the target", slog.String("handler", "passthrough"), slog.String("target", string(destAddr)), producer.ErrAttr(err))
		return nil
	}
	defer targetConn.Close()

	logger.Info("starting passthrough", slog.String("source", srcAddr), slog.String("target", string(destAddr)), slog.String("handler", "passthrough"))

	errChan := make(chan error, 2)

	// Source to target
	go func() {
		_, err := io.Copy(targetConn, conn)
		errChan <- err
	}()

	// Target to source
	go func() {
		_, err := io.Copy(conn, targetConn)
		errChan <- err
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
