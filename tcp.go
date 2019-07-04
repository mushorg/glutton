package glutton

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

func storePayload(data []byte, handler string, g *Glutton) error {
	sum := sha256.Sum256(data)
	if err := os.MkdirAll("payloads", os.ModePerm); err != nil {
		return err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join("payloads", sha256Hash)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.Write(data)
	if err != nil {
		return err
	}
	g.logger.Info(
		fmt.Sprintf("new payload stored from %s", handler),
		zap.String("handler", handler),
		zap.String("sha256", sha256Hash),
	)
	return nil
}

// HandleTCP takes a net.Conn and peeks at the data send
func (g *Glutton) HandleTCP(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[log.tcp ] error: %v", err))
		}
	}()
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		g.logger.Error(fmt.Sprintf("[log.tcp ] error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := g.processor.Connections.GetByFlow(ck)
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[log.tcp ] error: %v", err))
	}
	if n > 0 && n < 1024 {
		g.logger.Info(
			fmt.Sprintf("Packet got handled by TCP handler"),
			zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			zap.String("src_ip", host),
			zap.String("src_port", port),
			zap.String("handler", "tcp"),
			zap.String("payload_hex", hex.EncodeToString(buffer[0:n])),
		)
	}
	return storePayload(buffer, "tcp", g)
}
