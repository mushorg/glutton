package tcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type parsedTCP struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type tcpServer struct {
	events []parsedTCP
}

func storePayload(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	if err := os.MkdirAll("payloads", os.ModePerm); err != nil {
		return "", err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join("payloads", sha256Hash)
	if _, err := os.Stat(path); err == nil {
		return "", nil
	}
	out, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = out.Write(data)
	if err != nil {
		return "", err
	}
	return sha256Hash, nil
}

func (s *tcpServer) sendRandom(conn net.Conn) error {
	randomBytes := make([]byte, 12+rand.Intn(500))
	if _, err := rand.Read(randomBytes); err != nil {
		return err
	}
	s.events = append(s.events, parsedTCP{
		Direction:   "write",
		PayloadHash: hex.EncodeToString(randomBytes),
		Payload:     randomBytes,
	})
	if _, err := conn.Write(randomBytes); err != nil {
		return err
	}
	return nil
}

// HandleTCP takes a net.Conn and peeks at the data send
func HandleTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := tcpServer{
		events: []parsedTCP{},
	}

	defer func() {
		if err := h.ProduceTCP("tcp", conn, md, helpers.FirstOrEmpty[parsedTCP](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce message", zap.String("protocol", "tcp"), zap.Error(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close TCP connection", zap.String("handler", "tcp"), zap.Error(err))
		}
	}()

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("faild to split remote address: %w", err)
	}

	msgLength := 0
	data := []byte{}
	buffer := make([]byte, 1024)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Error("read error", zap.String("handler", "tcp"), zap.Error(err))
			break
		}
		msgLength += n
		data = append(data, buffer[:n]...)
		if n < 1024 {
			break
		}
		if msgLength > viper.GetInt("max_tcp_payload") {
			logger.Debug("max message length reached", zap.String("handler", "tcp"))
			break
		}
	}

	if msgLength > 0 {
		payloadHash, err := storePayload(data)
		if err != nil {
			return err
		}
		logger.Info(
			"Packet got handled by TCP handler",
			zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			zap.String("src_ip", host),
			zap.String("src_port", port),
			zap.String("handler", "tcp"),
			zap.String("payload_hash", payloadHash),
		)
		logger.Info(fmt.Sprintf("TCP payload:\n%s", hex.Dump(data[:msgLength%1024])))

		server.events = append(server.events, parsedTCP{
			Direction:   "read",
			PayloadHash: payloadHash,
			Payload:     data[:msgLength%1024],
		})
	}

	// sending some random data
	if err := server.sendRandom(conn); err != nil {
		logger.Error("write error", zap.String("handler", "tcp"), zap.Error(err))
	}

	return nil
}
