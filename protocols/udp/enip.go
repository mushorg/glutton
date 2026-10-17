package udp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/enip"
)

const maxENIPPayload = 1024

// enipScrubbedIP replaces the sensor address advertised in ListIdentity
// replies when the frame is recorded; the sanitizer only rewrites text.
var enipScrubbedIP = net.IPv4(1, 2, 3, 4)

type parsedENIP struct {
	Direction     string `json:"direction,omitempty"`      // "read" (from attacker) or "write" (from honeypot)
	Command       string `json:"command,omitempty"`        // encapsulation command, e.g. ListIdentity; "malformed" for a partial header
	SessionHandle uint32 `json:"session_handle,omitempty"` // header session handle
	SenderContext string `json:"sender_context,omitempty"` // hex of the 8-byte sender context
	Status        string `json:"status,omitempty"`         // write encapsulation status, e.g. success
	Payload       []byte `json:"payload,omitempty"`
	Truncated     bool   `json:"truncated,omitempty"`
}

// HandleENIP answers the EtherNet/IP list commands (ListIdentity,
// ListServices, ListInterfaces) with the same adapter identity as the TCP
// handler. Other commands are recorded only. Replies go to the datagram's
// source through ReplyUDP, so the reply budget applies.
func HandleENIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxENIPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedENIP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("enip", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedENIP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "enip"), producer.ErrAttr(err))
		}
	}()

	frame := parsedENIP{Direction: "read", Payload: payload, Truncated: len(data) > maxENIPPayload}
	hdr, err := enip.ParseHeader(payload)
	if err != nil {
		frame.Command = "malformed"
		frame.Truncated = true
		events = append(events, frame)
		logger.Debug("Failed to parse EtherNet/IP request", slog.String("protocol", "enip"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = enip.CommandName(hdr.Command)
	frame.SessionHandle = hdr.SessionHandle
	frame.SenderContext = hex.EncodeToString(hdr.SenderContext[:])
	events = append(events, frame)

	logger.Info("EtherNet/IP request received",
		slog.String("handler", "enip"),
		slog.String("protocol", "enip"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	var resp, recorded []byte
	switch hdr.Command {
	case enip.CmdListIdentity:
		id := enip.DefaultIdentity
		id.SerialNumber = enip.Serial()
		ip := dstAddr.IP.To4()
		if ip == nil {
			ip = net.IPv4zero
		}
		resp = enip.ListIdentityReply(hdr, id, ip, uint16(dstAddr.Port))
		recorded = enip.ListIdentityReply(hdr, id, enipScrubbedIP, uint16(dstAddr.Port))
	case enip.CmdListServices:
		resp = enip.ListServicesReply(hdr)
	case enip.CmdListInterfaces:
		resp = enip.ListInterfacesReply(hdr)
	default:
		return nil
	}
	if recorded == nil {
		recorded = resp
	}

	events = append(events, parsedENIP{
		Direction:     "write",
		Command:       frame.Command,
		SessionHandle: hdr.SessionHandle,
		SenderContext: frame.SenderContext,
		Status:        enip.StatusName(enip.StatusSuccess),
		Payload:       recorded,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send EtherNet/IP reply", slog.String("protocol", "enip"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
