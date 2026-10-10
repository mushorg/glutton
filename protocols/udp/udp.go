package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"
	"github.com/mushorg/glutton/protocols/udp/a2s"
	"github.com/mushorg/glutton/protocols/udp/ddp"
	"github.com/mushorg/glutton/protocols/udp/dtls"
	"github.com/mushorg/glutton/protocols/udp/ike"
	"github.com/mushorg/glutton/protocols/udp/knx"
	"github.com/mushorg/glutton/protocols/udp/rtps"
	"github.com/mushorg/glutton/protocols/udp/wsd"
)

const maxUDPPayload = 1024

type parsedUDP struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	if sipproto.LooksLikeSIP(data) {
		return HandleSIP(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if looksLikeRakNet(data) {
		return HandleRakNet(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if looksLikeKerberos(data) {
		return HandleKerberos(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if looksLikeCoAP(data) {
		return HandleCoAP(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if ike.LooksLikeIKE(data) {
		return HandleIKE(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if a2s.LooksLikeA2S(data) {
		return HandleA2S(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if ddp.LooksLikeDDP(data) {
		return HandleDDP(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if knx.LooksLikeKNX(data) {
		return HandleKNX(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if dtls.LooksLikeDTLS(data) {
		return HandleDTLS(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if rtps.LooksLikeRTPS(data) {
		return HandleRTPS(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if wsd.LooksLikeWSD(data) {
		return HandleWSDiscovery(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	if looksLikeHiFlying(srcAddr, data) {
		return HandleHiFlying(ctx, srcAddr, dstAddr, data, md, log, h)
	}

	truncated := len(data) > maxUDPPayload
	payload := make([]byte, min(len(data), maxUDPPayload))
	copy(payload, data[:len(payload)])

	hash := ""
	if len(payload) > 0 {
		hash = helpers.SHA256Hex(payload)
	}
	events := []parsedUDP{{
		Direction:   "read",
		Payload:     payload,
		PayloadHash: hash,
		Truncated:   truncated,
	}}
	defer func() {
		md.EndReason = connection.EndHandlerClose
		if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedUDP](events).Payload, events); err != nil {
			log.Error("Failed to produce message", slog.String("protocol", "udp"), producer.ErrAttr(err))
		}
	}()

	if _, err := helpers.Store(payload, "payloads"); err != nil {
		log.Error("failed to store UDP payload", slog.String("protocol", "udp"), producer.ErrAttr(err))
	}
	return nil
}
