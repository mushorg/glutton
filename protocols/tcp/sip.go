package tcp

import (
	"context"
	"log/slog"
	"net"
	"net/http"

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
	Direction string
	Payload   []byte
	Message   sip.Message
}

type sipServer struct {
	events []parsedSIP
}

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := sipServer{
		events: []parsedSIP{},
	}
	defer func() {
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
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "sip"), producer.ErrAttr(err))
			break
		}

		msg, err := pp.ParseMessage(buffer[:n])
		if err != nil {
			return err
		}

		server.events = append(server.events, parsedSIP{
			Direction: "read",
			Message:   msg,
			Payload:   buffer[:n],
		})

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
				server.events = append(server.events, parsedSIP{
					Direction: "write",
					Message:   resp,
					Payload:   []byte(resp.String()),
				})
				if _, err := conn.Write([]byte(resp.String())); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
