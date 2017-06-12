package glutton

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
)

func readFTP(conn net.Conn, g *Glutton) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		g.logger.Error(fmt.Sprintf("[ftp     ] error: %v", err))
	}
	g.logger.Info(fmt.Sprintf("[ftp     ] recv: %q", msg))
	return
}

// HandleFTP takes a net.Conn and does basic FTP communication
func (g *Glutton) HandleFTP(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[ftp     ]  error: %v", err))
		}
	}()

	conn.Write([]byte("220 Welcome!\r\n"))
	for {
		g.updateConnectionTimeout(ctx, conn)
		msg, err := readFTP(conn, g)
		if len(msg) < 4 || err != nil {
			break
		}
		cmd := strings.ToUpper(msg[:4])
		if cmd == "USER" {
			conn.Write([]byte("331 OK.\r\n"))
		} else if cmd == "PASS" {
			conn.Write([]byte("230 OK.\r\n"))
		} else {
			conn.Write([]byte("200 OK.\r\n"))
		}
	}
	return nil
}
