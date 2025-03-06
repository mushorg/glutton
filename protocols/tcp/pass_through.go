package tcp

import (
	"context"
	"fmt"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"io"
	"log/slog"
	"net"
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

	destAddr := conn.LocalAddr().String()
	targetConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer targetConn.Close()

	errChan := make(chan error, 2)
	// 创建双向数据传输的通道

	// 源到目标
	go func() {
		_, err := io.Copy(targetConn, conn)
		errChan <- err
	}()

	// 目标到源
	go func() {
		_, err := io.Copy(conn, targetConn)
		errChan <- err
	}()

	// 等待任一方向完成或出错
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
