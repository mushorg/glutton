package udp

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const maxUDPPayload = 1024

type parsedUDP struct {
	Direction string `json:"direction,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
}

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	if looksLikeRakNet(data) {
		return HandleRakNet(ctx, srcAddr, dstAddr, data, md, log, h)
	}

	payload := make([]byte, min(len(data), maxUDPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedUDP{{
		Direction: "read",
		Payload:   payload,
	}}
	defer func() {
		if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedUDP](events).Payload, events); err != nil {
			log.Error("Failed to produce message", slog.String("protocol", "udp"), producer.ErrAttr(err))
		}
	}()

	log.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(payload)))
	if _, err := helpers.Store(payload, "payloads"); err != nil {
		log.Error("failed to store UDP payload", slog.String("protocol", "udp"), producer.ErrAttr(err))
	}
	return nil
}
