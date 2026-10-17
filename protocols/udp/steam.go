package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/steam"
)

const maxSteamPayload = 1024

type parsedSteam struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	ClientID    string `json:"client_id,omitempty"` // decimal uint64
	MsgType     uint32 `json:"msg_type,omitempty"`  // 0 (discovery) is omitted; see command
	SequenceNum uint32 `json:"sequence_num,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// HandleSteam parses a Steam Remote Play discovery datagram and emits one
// producer event. It is parse-only: the Status reply a real client sends is
// larger than the probe, so answering would amplify.
func HandleSteam(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSteamPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSteam{}
	defer func() {
		md.EndReason = connection.EndHandlerClose
		if err := h.ProduceUDP("steam", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSteam](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "steam"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	msg, err := steam.Parse(payload)
	frame := parsedSteam{
		Direction: "read",
		Command:   "UNKNOWN",
		ClientID:  msg.ClientIDString(),
		Payload:   payload,
		Truncated: len(data) > maxSteamPayload,
	}
	if msg.HasHeader {
		frame.Command = steam.Name(msg.MsgType)
		frame.MsgType = uint32(msg.MsgType)
		frame.SequenceNum = msg.SequenceNum
	}
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse Steam datagram", slog.String("protocol", "steam"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("Steam Remote Play datagram received",
		slog.String("handler", "steam"),
		slog.String("protocol", "steam"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)
	return nil
}
