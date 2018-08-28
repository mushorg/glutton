package glutton

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

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
			zap.Uint16("dport", md.TargetPort),
			zap.String("saddr", host),
			zap.String("sport", port),
			zap.String("handler", "tcp"),
			zap.String("data_hex", hex.EncodeToString(buffer[0:n])),
		)
	}
	return err
}
