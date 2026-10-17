package tcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/nvms9000"
)

const maxNVMSFrames = 16

// nvmsIdentity is the persona in basic config replies; it is random per
// process so sensors differ, and tests swap it.
var nvmsIdentity = sync.OnceValue(nvms9000.RandomIdentity)

type parsedNVMS struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`    // operation name (queryBasicCfg)
	CommandID uint32 `json:"command_id,omitempty"` // header command id
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type nvmsServer struct {
	events []parsedNVMS
	conn   net.Conn
}

func (s *nvmsServer) write(frame parsedNVMS, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

// HandleNVMS9000 answers the TVT NVMS-9000 DVR management protocol: a
// queryBasicCfg request gets a device description, every other operation
// (including logins) a failure.
func HandleNVMS9000(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &nvmsServer{events: []parsedNVMS{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("nvms9000", conn, md, helpers.FirstOrEmpty[parsedNVMS](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "nvms9000"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close NVMS-9000 connection", slog.String("protocol", "nvms9000"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxNVMSFrames; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "nvms9000"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		frame, raw, err := nvms9000.ReadFrame(conn)
		if err != nil {
			if len(raw) > 0 {
				server.events = append(server.events, parsedNVMS{
					Direction: "read",
					Payload:   raw,
					Truncated: errors.Is(err, nvms9000.ErrTooLarge),
				})
			}
			switch {
			case errors.Is(err, nvms9000.ErrBadMagic), errors.Is(err, nvms9000.ErrBadLen), errors.Is(err, nvms9000.ErrTooLarge):
				endReason = connection.EndReadError
			case errors.Is(err, io.ErrUnexpectedEOF):
				// the client closed mid-frame
				endReason = connection.EndClientClose
			default:
				endReason = connection.EndReasonFromRead(err)
			}
			if !errors.Is(err, io.EOF) {
				logger.Debug("Failed to read data", slog.String("protocol", "nvms9000"), producer.ErrAttr(err))
			}
			return nil
		}

		req := nvms9000.ParseRequest(frame.Body)
		read := parsedNVMS{
			Direction: "read",
			Command:   req.Operation,
			CommandID: frame.Header.Command,
			Username:  req.Username,
			Payload:   raw,
		}
		if user, pass := nvms9000.Credentials(req.XML); pass != "" || user != "" {
			if user != "" {
				read.Username = user
			}
			read.Password = pass
		}
		server.events = append(server.events, read)
		logger.Info("NVMS-9000 request",
			slog.String("handler", "nvms9000"),
			slog.String("protocol", "nvms9000"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("command", req.Operation),
		)

		reply, status := nvms9000.FailXML(), "fail"
		if req.Operation == "queryBasicCfg" {
			reply, status = nvms9000.BasicCfgXML(nvmsIdentity()), "success"
		}
		out := nvms9000.Build(frame.Header, []byte(reply))
		if err := server.write(parsedNVMS{Command: req.Operation, CommandID: frame.Header.Command, Status: status}, out); err != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "nvms9000"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
