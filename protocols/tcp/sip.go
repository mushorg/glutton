package tcp

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

const maxBufferSize = 1024

type parsedSIP struct {
	Direction string      `json:"direction,omitempty"`
	Command   string      `json:"command,omitempty"`
	Status    string      `json:"status,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
	Message   sip.Message `json:"message,omitempty"`
}

type sipServer struct {
	events []parsedSIP
}

func sipDecoded(direction string, msg sip.Message, payload []byte) parsedSIP {
	frame := parsedSIP{Direction: direction, Message: msg, Payload: payload}
	if msg == nil {
		return frame
	}
	switch m := msg.(type) {
	case sip.Request:
		frame.Command = string(m.Method())
	case sip.Response:
		frame.Status = strconv.Itoa(int(m.StatusCode()))
	}
	return frame
}

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := sipServer{
		events: []parsedSIP{},
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("sip", conn, md, helpers.FirstOrEmpty[parsedSIP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SIP connection", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	buffer := make([]byte, maxBufferSize)
	l := log.NewDefaultLogrusLogger()
	pp := parser.NewPacketParser(l)

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}

		payload := make([]byte, n)
		copy(payload, buffer[:n])
		msg, err := pp.ParseMessage(payload)
		if err != nil {
			server.events = append(server.events, sipDecoded("read", nil, payload))
			return err
		}

		server.events = append(server.events, sipDecoded("read", msg, payload))

		switch msg := msg.(type) {
		case sip.Request:
			switch msg.Method() {
			case sip.REGISTER:
				logger.Info("handling SIP register")
			case sip.INVITE:
				logger.Info("handling SIP invite")
			case sip.OPTIONS:
				logger.Info("handling SIP options")
				resp := sip.NewResponseFromRequest(
					msg.MessageID(),
					msg,
					http.StatusOK,
					"",
					"",
				)
				respBytes := []byte(resp.String())
				server.events = append(server.events, sipDecoded("write", resp, respBytes))
				if _, err := conn.Write(respBytes); err != nil {
					endReason = connection.EndWriteError
					return err
				}
			}
		}
	}
	return nil
}
