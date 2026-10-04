package udp

import (
	"bytes"
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const maxRakNetPayload = 1024

// RakNet offline-message magic (Minecraft Bedrock / RakNet).
var raknetMagic = []byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

// Offline / unconnected packet IDs commonly seen in internet scans.
var raknetPacketNames = map[uint8]string{
	0x01: "UNCONNECTED_PING",
	0x02: "UNCONNECTED_PING_OPEN_CONNECTIONS",
	0x05: "OPEN_CONNECTION_REQUEST_1",
	0x06: "OPEN_CONNECTION_REPLY_1",
	0x07: "OPEN_CONNECTION_REQUEST_2",
	0x08: "OPEN_CONNECTION_REPLY_2",
	0x1c: "UNCONNECTED_PONG",
}

type parsedRakNet struct {
	Direction  string `json:"direction,omitempty"`
	Command    string `json:"command,omitempty"`
	PacketID   uint8  `json:"packet_id,omitempty"`
	PacketName string `json:"packet_name,omitempty"`
	Protocol   uint8  `json:"protocol,omitempty"`
	MagicOK    bool   `json:"magic_ok,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

func raknetPacketName(id uint8) string {
	if name, ok := raknetPacketNames[id]; ok {
		return name
	}
	return "UNKNOWN"
}

func raknetMagicOffset(id uint8) int {
	switch id {
	case 0x01, 0x02:
		return 9 // ID + 8-byte timestamp
	default:
		return 1 // ID immediately followed by magic
	}
}

func looksLikeRakNet(data []byte) bool {
	return bytes.Contains(data, raknetMagic)
}

func parseRakNet(data []byte, datagramLen int) parsedRakNet {
	frame := parsedRakNet{Direction: "read", Payload: data}
	if len(data) == 0 {
		return frame
	}

	frame.PacketID = data[0]
	frame.PacketName = raknetPacketName(frame.PacketID)
	frame.Command = frame.PacketName

	off := raknetMagicOffset(frame.PacketID)
	if off >= 0 && off+len(raknetMagic) <= len(data) && bytes.Equal(data[off:off+len(raknetMagic)], raknetMagic) {
		frame.MagicOK = true
		if frame.PacketID == 0x05 {
			protoOff := off + len(raknetMagic)
			if protoOff < len(data) {
				frame.Protocol = data[protoOff]
			}
			frame.MTU = datagramLen
		}
		return frame
	}

	if looksLikeRakNet(data) {
		frame.MagicOK = true
	}
	return frame
}

// HandleRakNet parses a RakNet / Minecraft Bedrock UDP datagram and emits one
// producer event with packet id / name tagged in decoded. It does not reply:
// answering Open Connection Reply 1 or Unconnected Pong would advertise a
// Bedrock server. Parse-only is enough to tag scanner OCR1 / ping probes.
func HandleRakNet(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRakNetPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRakNet{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("raknet", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRakNet](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "raknet"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame := parseRakNet(payload, len(data))
	frame.Truncated = len(data) > maxRakNetPayload
	events = append(events, frame)

	if !frame.MagicOK {
		logger.Debug("RakNet packet missing offline magic",
			slog.String("protocol", "raknet"),
			slog.Int("bytes", len(payload)),
			slog.Int("packet_id", int(frame.PacketID)),
		)
	}

	logger.Info("RakNet UDP packet received",
		slog.String("handler", "raknet"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("packet_name", frame.PacketName),
		slog.Int("packet_id", int(frame.PacketID)),
		slog.Bool("magic_ok", frame.MagicOK),
	)
	return nil
}
