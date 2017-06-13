package glutton

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
)

// HandleTCP takes a net.Conn and peeks at the data send
func (g *Glutton) HandleTCP(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[log.tcp ] error: %v", err))
		}
	}()
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[log.tcp ] error: %v", err))
	}
	if n > 0 && n < 1024 {
		g.logger.Info(fmt.Sprintf("[log.tcp ] %s\n%s", host, hex.Dump(buffer[0:n])))
	}
	return err
}
