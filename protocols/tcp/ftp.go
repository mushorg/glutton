package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type parsedFTP struct {
	Direction string `json:"direction,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
}

type ftpServer struct {
	events []parsedFTP
	conn   net.Conn
}

func (s *ftpServer) read(_ interfaces.Logger, _ interfaces.Honeypot) (string, error) {
	msg, err := bufio.NewReader(s.conn).ReadString('\n')
	if err != nil {
		return msg, err
	}
	s.events = append(s.events, parsedFTP{
		Direction: "read",
		Payload:   []byte(msg),
	})
	return msg, nil
}

func (s *ftpServer) write(msg string) error {
	_, err := s.conn.Write([]byte(msg))
	if err != nil {
		return err
	}
	s.events = append(s.events, parsedFTP{
		Direction: "write",
		Payload:   []byte(msg),
	})
	return nil
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := ftpServer{
		conn: conn,
	}
	defer func() {
		if err := h.ProduceTCP("ftp", conn, md, helpers.FirstOrEmpty[parsedFTP](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce events", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close FTP connection", producer.ErrAttr(err))
		}
	}()

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte("220 Welcome!\r\n")); err != nil {
		return err
	}
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		msg, err := server.read(logger, h)
		if err != nil || err != io.EOF {
			return err
		}
		if len(msg) < 4 {
			continue
		}
		cmd := strings.ToUpper(msg[:4])

		logger.Info(
			"ftp payload received",
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("message", fmt.Sprintf("%q", msg)),
			slog.String("handler", "ftp"),
		)

		var resp string
		switch cmd {
		case "USER":
			resp = "331 OK.\r\n"
		case "PASS":
			resp = "230 OK.\r\n"
		default:
			resp = "200 OK.\r\n"
		}
		if err := server.write(resp); err != nil {
			return err
		}
	}
}
