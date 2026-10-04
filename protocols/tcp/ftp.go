package tcp

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	// 1xx
	StatusFileStatusOK = 150 // RFC 959, 4.2.1
	// 2xx
	StatusOK                 = 200 // RFC 959, 4.2.1
	StatusServiceReady       = 220 // RFC 959, 4.2.1
	StatusClosingControlConn = 221 // RFC 959, 4.2.1
	StatusClosingDataConn    = 226 // RFC 959, 4.2.1
	StatusUserLoggedIn       = 230 // RFC 959, 4.2.1
	// 3xx
	StatusUserOK = 331 // RFC 959, 4.2.1
	// 4xx
	StatusCannotOpenDataConnection = 425 // RFC 959, 4.2.1
	// 5xx
	StatusActionNotTaken = 550 // RFC 959, 4.2.1
)

type parsedFTP struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Path        string `json:"path,omitempty"`
	Status      string `json:"status,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type ftpServer struct {
	events []parsedFTP
	conn   net.Conn
}

type ftpResponse struct {
	code int
	msg  string
}

func ftpVerbAndPath(msg string) (cmd, path string) {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) == 0 {
		return "", ""
	}
	cmd = strings.ToUpper(fields[0])
	if len(fields) > 1 && (cmd == "STOR" || cmd == "RETR" || cmd == "CWD") {
		path = fields[1]
	}
	return cmd, path
}

func (s *ftpServer) read(_ interfaces.Logger, _ interfaces.Honeypot) (string, error) {
	msg, err := bufio.NewReader(s.conn).ReadString('\n')
	if err != nil {
		return msg, err
	}
	cmd, path := ftpVerbAndPath(msg)
	s.events = append(s.events, parsedFTP{
		Direction: "read",
		Command:   cmd,
		Path:      path,
		Payload:   []byte(msg),
	})
	return msg, nil
}

func (s *ftpServer) write(resp ftpResponse) error {
	msg := fmt.Sprintf("%d %s\r\n", resp.code, resp.msg)
	_, err := s.conn.Write([]byte(msg))
	if err != nil {
		return err
	}
	s.events = append(s.events, parsedFTP{
		Direction: "write",
		Status:    strconv.Itoa(resp.code),
		Payload:   []byte(msg),
	})
	return nil

}

func (s *ftpServer) ftpSTOR(ip string, port int, path string) (ftpResponse, string) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ftpResponse{StatusCannotOpenDataConnection, "Failed to establish connection."}, ""
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return ftpResponse{StatusActionNotTaken, "Failed to establish connection."}, ""
	}
	buffer := make([]byte, maxBufferSize)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ftpResponse{StatusActionNotTaken, "Failed to read file."}, ""
	}

	fileHash, err := helpers.Store(buffer, filepath.Join("payloads", "ftp"))
	if err != nil {
		return ftpResponse{StatusActionNotTaken, "Failed to store file."}, ""
	}

	s.events = append(s.events, parsedFTP{
		Direction:   "read",
		Command:     "STOR",
		Path:        path,
		PayloadHash: fileHash,
		Payload:     buffer,
	})

	if err := conn.Close(); err != nil {
		return ftpResponse{StatusActionNotTaken, "Failed to close connection."}, ""
	}
	return ftpResponse{StatusClosingDataConn, "File received."}, fileHash
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := ftpServer{
		conn: conn,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("ftp", conn, md, helpers.FirstOrEmpty[parsedFTP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce events", slog.String("protocol", "ftp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close FTP connection", slog.String("protocol", "ftp"), producer.ErrAttr(err))
		}
	}()

	host, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	if err := server.write(ftpResponse{StatusServiceReady, "Welcome"}); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	var portParam string
loop:
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "ftp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		msg, err := server.read(logger, h)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "ftp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
		if len(msg) < 4 {
			continue
		}
		cmd, path := ftpVerbAndPath(msg)

		logger.Info(
			"ftp command received",
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
			slog.String("message", fmt.Sprintf("%q", msg)),
			slog.String("handler", "ftp"),
		)

		var (
			resp     ftpResponse
			filehash string
		)
		switch cmd {
		case "USER":
			resp = ftpResponse{StatusUserOK, "Ok."}
		case "PASS":
			resp = ftpResponse{StatusUserLoggedIn, "Ok."}
		case "STOR":
			parts := strings.Split(portParam, ",")
			ip := strings.Join(parts[:4], ".")

			portByte1, err := strconv.Atoi(parts[4])
			if err != nil {
				return err
			}
			portByte2, err := strconv.Atoi(strings.TrimSpace(parts[5]))
			if err != nil {
				return err
			}

			port := portByte1<<8 + portByte2
			if err := server.write(ftpResponse{StatusFileStatusOK, fmt.Sprintf("Connecting to port %d\r\n", port)}); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			resp, filehash = server.ftpSTOR(ip, port, path)
			if filehash != "" {
				logger.Info(
					"FTP payload receievd",
					slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
					slog.String("src_ip", host),
					slog.String("src_port", srcPort),
					slog.String("handler", "ftp"),
					slog.String("payload_hash", filehash),
				)
			}
		case "QUIT":
			if err := server.write(ftpResponse{StatusClosingControlConn, "Goodbye."}); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			break loop
		case "PORT":
			portParam = msg[5:]
			resp = ftpResponse{StatusOK, "PORT command successful."}
		default:
			resp = ftpResponse{StatusOK, "Ok."}
		}
		if err := server.write(resp); err != nil {
			endReason = connection.EndWriteError
			return err
		}
	}
	return nil
}
