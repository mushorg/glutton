package protocols

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"go.uber.org/zap"
)

const maxBufferSize = 1024

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Errorf("failed to close SIP connection: %w", err).Error())
		}
	}()

	buffer := make([]byte, maxBufferSize)

	_, err := conn.Read(buffer)
	if err != nil {
		return err
	}

	pp := parser.NewPacketParser(nil)
	msg, err := pp.ParseMessage(buffer)
	if err != nil {
		return err
	}

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}
	if err := h.Produce("sip", conn, md, buffer, msg); err != nil {
		logger.Error("failed to produce message", zap.String("protocol", "sip"), zap.Error(err))
	}

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
			if _, err := conn.Write([]byte(resp.String())); err != nil {
				return err
			}
		}
	}
	return nil
}
