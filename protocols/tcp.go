package protocols

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

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

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

// HandleTCP takes a net.Conn and peeks at the data send
func HandleTCP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close TCP connection", zap.String("handler", "tcp"), zap.Error(err))
		}
	}()
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("faild to split remote address: %w", err)
	}
	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return fmt.Errorf("failed to get metadata: %w", err)
	}

	msgLength := 0
	data := []byte{}
	for {
		buffer := make([]byte, 1024)
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
		dstPort := "0"
		if md != nil {
			dstPort = strconv.Itoa(int(md.TargetPort))
		}
		logger.Info(
			"Packet got handled by TCP handler",
			zap.String("dest_port", dstPort),
			zap.String("src_ip", host),
			zap.String("src_port", port),
			zap.String("handler", "tcp"),
			zap.String("payload_hash", payloadHash),
		)
		if err := h.Produce("tcp", conn, md, data, struct {
			PayloadHash string `json:"payload_hash,omitempty"`
		}{PayloadHash: payloadHash}); err != nil {
			logger.Error("failed to produce message", zap.String("protocol", "tcp"), zap.Error(err))
		}
		logger.Info(fmt.Sprintf("TCP payload:\n%s", hex.Dump(data[:msgLength%1024])))
	}

	// sending some randome data
	randomBytes := make([]byte, 12+rand.Intn(500))
	if _, err = rand.Read(randomBytes); err != nil {
		return err
	}
	if _, err = conn.Write(randomBytes); err != nil {
		return err
	}

	return nil
}
