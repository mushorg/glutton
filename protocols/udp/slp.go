package udp

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/slp"
)

const maxSLPPayload = 1024

type parsedSLP struct {
	Direction   string `json:"direction,omitempty"`    // "read" (from attacker) or "write" (from honeypot)
	Command     string `json:"command,omitempty"`      // SrvRqst, AttrRqst, ...; "malformed" for an unparseable datagram
	XID         string `json:"xid,omitempty"`          // hex transaction ID, e.g. 0xc0e8
	Lang        string `json:"lang,omitempty"`         // language tag
	ServiceType string `json:"service_type,omitempty"` // SrvRqst/SrvTypeRqst service type or naming authority
	Scope       string `json:"scope,omitempty"`        // scope list
	Predicate   string `json:"predicate,omitempty"`    // LDAPv3 search filter of a SrvRqst
	URL         string `json:"url,omitempty"`          // AttrRqst URL or service type
	Status      string `json:"status,omitempty"`       // write error code name, e.g. SCOPE_NOT_SUPPORTED
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// HandleSLP answers SLPv2 SrvRqst, SrvTypeRqst and AttrRqst datagrams with an
// empty reply (SCOPE_NOT_SUPPORTED unless the scope list names "default").
// Registrations and other functions are recorded only. Multicast requests are
// never answered. Replies go through ReplyUDP and are always smaller than the
// request, so the sensor is no amplifier.
func HandleSLP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSLPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSLP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("slp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSLP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "slp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedSLP{Direction: "read", Payload: payload, Truncated: len(data) > maxSLPPayload}
	hdr, err := slp.ParseHeader(data)
	if err != nil && hdr.Function == 0 {
		frame.Command = "malformed"
		frame.Truncated = true
		events = append(events, frame)
		logger.Debug("Failed to parse SLP header", slog.String("protocol", "slp"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}
	frame.Command = slp.FunctionName(hdr.Function)
	frame.XID = fmt.Sprintf("0x%04x", hdr.XID)
	frame.Lang = hdr.Lang
	if err != nil {
		// header was readable but the length or language tag is inconsistent
		frame.Truncated = true
		events = append(events, frame)
		logger.Debug("Failed to parse SLP message", slog.String("protocol", "slp"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}

	req, perr := slp.ParseRequest(data, hdr)
	frame.ServiceType, frame.Scope, frame.Predicate, frame.URL = req.ServiceType, req.Scope, req.Predicate, req.URL
	if perr != nil {
		frame.Truncated = true
	}
	events = append(events, frame)
	if perr != nil {
		logger.Debug("Failed to parse SLP body", slog.String("protocol", "slp"), producer.ErrAttr(perr))
		return nil
	}

	logger.Info("SLP request received",
		slog.String("handler", "slp"),
		slog.String("protocol", "slp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	resp, code := slp.Reply(hdr, req)
	if resp == nil || len(resp) >= len(data) {
		return nil
	}
	events = append(events, parsedSLP{
		Direction: "write",
		Command:   slp.FunctionName(resp[1]),
		XID:       frame.XID,
		Lang:      hdr.Lang,
		Status:    slp.ErrorName(code),
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send SLP reply", slog.String("protocol", "slp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
