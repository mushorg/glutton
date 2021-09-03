package protocols

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

func readFTP(conn net.Conn, logger Logger, h Honeypot) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		logger.Error(fmt.Sprintf("[ftp     ] error: %v", err))
	}
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		logger.Error(fmt.Sprintf("[ftp     ] error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := h.ConnectionByFlow(ck)

	logger.Info(
		"ftp payload received",
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
		zap.String("msg", fmt.Sprintf("%q", msg)),
		zap.String("handler", "ftp"),
	)
	return
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("[ftp     ]  error: %v", err))
		}
	}()

	conn.Write([]byte("220 Welcome!\r\n"))
	for {
		h.UpdateConnectionTimeout(ctx, conn)
		msg, err := readFTP(conn, logger, h)
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
