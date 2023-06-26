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
	return msg, err
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close FTP connection", zap.Error(err))
		}
	}()

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte("220 Welcome!\r\n")); err != nil {
		return err
	}
	for {
		h.UpdateConnectionTimeout(ctx, conn)
		msg, err := readFTP(conn, logger, h)
		if len(msg) < 4 || err != nil {
			return err
		}
		cmd := strings.ToUpper(msg[:4])

		logger.Info(
			"ftp payload received",
			zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			zap.String("src_ip", host),
			zap.String("src_port", port),
			zap.String("message", fmt.Sprintf("%q", msg)),
			zap.String("handler", "ftp"),
		)
		if err := h.Produce("ftp", conn, md, []byte(msg), struct {
			Message string `json:"message,omitempty"`
		}{Message: msg}); err != nil {
			return err
		}

		if cmd == "USER" {
			conn.Write([]byte("331 OK.\r\n"))
		} else if cmd == "PASS" {
			conn.Write([]byte("230 OK.\r\n"))
		} else {
			conn.Write([]byte("200 OK.\r\n"))
		}
	}
}
