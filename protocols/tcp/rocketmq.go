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
	"github.com/mushorg/glutton/protocols/tcp/rocketmq"
)

const maxRocketMQMessages = 32

// newRocketMQBroker builds the broker persona; tests swap it to pin the clock.
var newRocketMQBroker = rocketmq.NewBroker

type parsedRocketMQ struct {
	Direction string            `json:"direction,omitempty"`
	Command   string            `json:"command,omitempty"`
	Code      int               `json:"code"`
	Opaque    int32             `json:"opaque"`
	Flag      int               `json:"flag,omitempty"`
	Language  string            `json:"language,omitempty"`
	Version   int               `json:"version,omitempty"`
	Remark    string            `json:"remark,omitempty"`
	Status    string            `json:"status,omitempty"`
	ExtFields map[string]string `json:"ext_fields,omitempty"`
	Config    map[string]string `json:"config,omitempty"`
	Payload   []byte            `json:"payload,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
}

type rocketMQServer struct {
	events []parsedRocketMQ
	conn   net.Conn
}

func (s *rocketMQServer) write(data []byte, frame parsedRocketMQ) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

func rocketMQReadFrame(f rocketmq.Frame) parsedRocketMQ {
	p := parsedRocketMQ{
		Direction: "read",
		Command:   rocketmq.RequestName(f.Header.Code),
		Code:      f.Header.Code,
		Opaque:    f.Header.Opaque,
		Flag:      f.Header.Flag,
		Language:  f.Header.Language,
		Version:   f.Header.Version,
		Remark:    f.Header.Remark,
		ExtFields: f.Header.ExtFields,
		Payload:   f.Raw,
	}
	switch f.Header.Code {
	case rocketmq.CodeUpdateBrokerConf, rocketmq.CodeUpdateNamesrvConf:
		p.Config = rocketmq.ParseProperties(f.Body)
	}
	return p
}

// HandleRocketMQ takes a net.Conn and emulates an Apache RocketMQ broker's
// remoting protocol (tcp/10911).
func HandleRocketMQ(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rocketMQServer{events: []parsedRocketMQ{}, conn: conn}
	broker := newRocketMQBroker()
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rocketmq", conn, md, helpers.FirstOrEmpty[parsedRocketMQ](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rocketmq"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RocketMQ connection", slog.String("protocol", "rocketmq"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxRocketMQMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rocketmq"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		f, err := rocketmq.ReadFrame(conn)
		if err != nil {
			if len(f.Raw) > 0 {
				server.events = append(server.events, parsedRocketMQ{
					Direction: "read", Payload: f.Raw,
					Truncated: errors.Is(err, rocketmq.ErrTooLarge) || errors.Is(err, io.ErrUnexpectedEOF),
				})
			}
			endReason = connection.EndReasonFromRead(err)
			if errors.Is(err, rocketmq.ErrMalformed) {
				endReason = connection.EndHandlerClose
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("Failed to read RocketMQ frame", slog.String("protocol", "rocketmq"), producer.ErrAttr(err))
			}
			break
		}
		frame := rocketMQReadFrame(f)
		server.events = append(server.events, frame)
		logger.Info(
			"RocketMQ request",
			slog.String("handler", "rocketmq"),
			slog.String("protocol", "rocketmq"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("command", frame.Command),
		)

		reply, code, ok := broker.Reply(f)
		if !ok {
			continue
		}
		out := parsedRocketMQ{
			Command: frame.Command,
			Code:    code,
			Opaque:  f.Header.Opaque,
			Flag:    rocketmq.FlagResponse,
			Status:  rocketmq.ResponseName(code),
		}
		if err := server.write(reply, out); err != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "rocketmq"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	if i >= maxRocketMQMessages {
		endReason = connection.EndMaxFrames
	}
	return nil
}
