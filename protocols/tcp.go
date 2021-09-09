package protocols

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kung-foo/freki"
	"github.com/pkg/errors"
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
func HandleTCP(ctx context.Context, conn net.Conn, log Logger, h Honeypot) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Error("failed to close TCP connection", zap.String("handler", "tcp"), zap.Error(err))
		}
	}()
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return errors.Wrap(err, "faild to split remote address")
	}
	ck := freki.NewConnKeyByString(host, port)
	md := h.ConnectionByFlow(ck)

	msgLength := 0
	data := []byte{}
	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Error("read error", zap.String("handler", "tcp"), zap.Error(err))
			break
		}
		msgLength += n
		data = append(data, buffer[:n]...)
		if n < 1024 {
			break
		}
		if msgLength > viper.GetInt("max_tcp_payload") {
			log.Debug("max message length reached", zap.String("handler", "tcp"))
			break
		}
	}

	if msgLength > 0 {
		payloadHash, err := storePayload(data)
		if err != nil {
			return err
		}
		log.Info(
			"Packet got handled by TCP handler",
			zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			zap.String("src_ip", host),
			zap.String("src_port", port),
			zap.String("handler", "tcp"),
			zap.String("payload_hex", hex.EncodeToString(data)),
			zap.String("payload_hash", payloadHash),
		)
	}
	return nil
}
