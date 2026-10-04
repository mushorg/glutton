package udp

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

const maxSIPPayload = 1024

type parsedSIP struct {
	Direction string      `json:"direction,omitempty"`
	Command   string      `json:"command,omitempty"`
	Status    string      `json:"status,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
	Message   sip.Message `json:"message,omitempty"`
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

// HandleSIP parses a UDP SIP datagram, answers OPTIONS with 200 OK, and emits
// one producer event with per-direction decoded frames (same shape as TCP SIP).
func HandleSIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSIPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSIP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
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
		events = append(events, sipDecoded("read", nil, payload))
		logger.Debug("Failed to parse SIP message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		endReason = connection.EndReadError
		return err
	}

	events = append(events, sipDecoded("read", msg, payload))

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
		events = append(events, sipDecoded("write", resp, respBytes))
		if err := h.ReplyUDP(srcAddr, dstAddr, respBytes); err != nil {
			logger.Error("Failed to reply to SIP OPTIONS", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	return nil
}
