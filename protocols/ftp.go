package protocols

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

func readFTP(conn net.Conn, logger Logger, h Honeypot) (string, error) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return msg, err
	}
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return msg, err
	}

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return "", err
	}

	if err := h.Produce(conn, md, []byte(msg)); err != nil {
		logger.Error("failed to produce message", zap.String("protocol", "ftp"), zap.Error(err))
	}

	logger.Info(
		"ftp payload received",
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
		zap.String("message", fmt.Sprintf("%q", msg)),
		zap.String("handler", "ftp"),
	)
	return msg, err
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close FTP connection", zap.Error(err))
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
