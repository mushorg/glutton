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
	"github.com/mushorg/glutton/protocols/tcp/sofia"
)

const (
	// sofiaMaxBody caps the stored frame body; real requests are a few hundred bytes.
	sofiaMaxBody = 64 * 1024
	// sofiaMaxRequests bounds the frames recorded for one connection.
	sofiaMaxRequests = 20
)

type parsedSofia struct {
	Direction string       `json:"direction,omitempty"`
	Header    sofia.Header `json:"header,omitempty"`
	Command   string       `json:"command,omitempty"` // JSON Name, else OprName, else "msg-<id>"
	Username  string       `json:"username,omitempty"`
	Password  string       `json:"password,omitempty"`
	Status    string       `json:"status,omitempty"` // named write outcome
	Payload   []byte       `json:"payload,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
}

type sofiaServer struct {
	events []parsedSofia
	conn   net.Conn
}

func (s *sofiaServer) read() (sofia.Request, error) {
	req, raw, truncated, err := sofia.ReadRequest(s.conn, sofiaMaxBody)
	if len(raw) == 0 {
		return req, err
	}
	frame := parsedSofia{Direction: "read", Payload: raw, Truncated: truncated}
	if len(raw) >= sofia.HeaderLen && req.Header.Head == sofia.Magic {
		frame.Header = req.Header
		frame.Command = req.CommandName()
		frame.Username = req.Username
		frame.Password = req.Password
	}
	s.events = append(s.events, frame)
	return req, err
}

func (s *sofiaServer) write(req sofia.Request, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	hdr, _ := sofia.ParseHeader(data)
	s.events = append(s.events, parsedSofia{
		Direction: "write",
		Header:    hdr,
		Command:   req.CommandName(),
		Status:    "ok",
		Payload:   data,
	})
	return nil
}

// HandleSofia takes a net.Conn and answers the XiongMai "Sofia" DVR protocol
// on tcp/34567. Every request is recorded and acknowledged with Ret 100; the
// commands (e.g. DebugShell) are never executed.
func HandleSofia(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &sofiaServer{events: []parsedSofia{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("sofia", conn, md, helpers.FirstOrEmpty[parsedSofia](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sofia"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Sofia connection", slog.String("protocol", "sofia"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < sofiaMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "sofia"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			if errors.Is(err, sofia.ErrBodyTooLarge) || errors.Is(err, sofia.ErrBadMagic) {
				logger.Debug("Invalid Sofia frame", slog.String("protocol", "sofia"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "sofia"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("Sofia request received",
				slog.String("handler", "sofia"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", req.CommandName()),
			)
		}
		if err := server.write(req, sofia.BuildResponse(req)); err != nil {
			logger.Error("Failed to write Sofia response", slog.String("protocol", "sofia"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
