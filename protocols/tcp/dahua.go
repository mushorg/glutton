package tcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/dahua"
)

const (
	// dahuaMaxBody caps the stored frame body; real logins are a few dozen bytes.
	dahuaMaxBody = 64 * 1024
	// dahuaMaxRequests bounds the frames recorded for one connection.
	dahuaMaxRequests = 20
)

type parsedDahua struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // "login" or "cmd-0xNN"
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Nonce     string `json:"nonce,omitempty"`  // client "Random:" value
	Status    string `json:"status,omitempty"` // named write outcome
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type dahuaServer struct {
	events []parsedDahua
	conn   net.Conn
}

func (s *dahuaServer) read() (dahua.Request, error) {
	req, raw, truncated, err := dahua.ReadRequest(s.conn, dahuaMaxBody)
	if len(raw) == 0 {
		return req, err
	}
	frame := parsedDahua{Direction: "read", Payload: raw, Truncated: truncated}
	if len(raw) >= dahua.HeaderLen {
		frame.Command = req.CommandName()
		frame.Username = req.Username
		frame.Password = req.Password
		frame.Nonce = req.Nonce
	}
	s.events = append(s.events, frame)
	return req, err
}

func (s *dahuaServer) write(data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedDahua{Direction: "write", Status: status, Payload: data})
	return nil
}

// HandleDahua takes a net.Conn and answers the Dahua DVR private protocol on
// tcp/37777. Login requests are recorded with their credentials and rejected.
func HandleDahua(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &dahuaServer{events: []parsedDahua{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("dahua", conn, md, helpers.FirstOrEmpty[parsedDahua](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dahua"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Dahua connection", slog.String("protocol", "dahua"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < dahuaMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "dahua"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			if errors.Is(err, dahua.ErrBodyTooLarge) {
				logger.Debug("Oversize Dahua frame", slog.String("protocol", "dahua"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "dahua"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("Dahua request received",
				slog.String("handler", "dahua"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", req.CommandName()),
			)
		}
		if !req.IsLogin() {
			continue
		}
		if err := server.write(dahua.BuildLoginResponse(dahua.StatusWrongPassword), "login-denied"); err != nil {
			logger.Error("Failed to write Dahua response", slog.String("protocol", "dahua"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
