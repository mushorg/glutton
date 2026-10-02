package udp

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

const maxSIPPayload = 1024

type parsedSIP struct {
	Direction string      `json:"direction,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
	Message   sip.Message `json:"message,omitempty"`
}

// HandleSIP parses a UDP SIP datagram, answers OPTIONS with 200 OK, and emits
// one producer event with per-direction decoded frames (same shape as TCP SIP).
func HandleSIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSIPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSIP{}
	defer func() {
		if err := h.ProduceUDP("sip", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSIP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	logger.Info("SIP UDP packet received",
		slog.String("handler", "sip"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
	)

	pp := parser.NewPacketParser(log.NewDefaultLogrusLogger())
	msg, err := pp.ParseMessage(payload)
	if err != nil {
		events = append(events, parsedSIP{Direction: "read", Payload: payload})
		logger.Debug("Failed to parse SIP message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return err
	}

	events = append(events, parsedSIP{
		Direction: "read",
		Message:   msg,
		Payload:   payload,
	})

	req, ok := msg.(sip.Request)
	if !ok {
		return nil
	}

	switch req.Method() {
	case sip.REGISTER:
		logger.Info("handling SIP register", slog.String("protocol", "sip"))
	case sip.INVITE:
		logger.Info("handling SIP invite", slog.String("protocol", "sip"))
	case sip.OPTIONS:
		logger.Info("handling SIP options", slog.String("protocol", "sip"))
		resp := sip.NewResponseFromRequest(
			req.MessageID(),
			req,
			http.StatusOK,
			"",
			"",
		)
		respBytes := []byte(resp.String())
		events = append(events, parsedSIP{
			Direction: "write",
			Message:   resp,
			Payload:   respBytes,
		})
		if err := h.ReplyUDP(srcAddr, dstAddr, respBytes); err != nil {
			logger.Error("Failed to reply to SIP OPTIONS", slog.String("protocol", "sip"), producer.ErrAttr(err))
			return err
		}
	}
	return nil
}
