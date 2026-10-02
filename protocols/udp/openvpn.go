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
)

const maxOpenVPNPayload = 1024

// OpenVPN packet opcodes (high 5 bits of the first byte).
var openVPNOpcodeNames = map[uint8]string{
	1: "P_CONTROL_HARD_RESET_CLIENT_V1",
	2: "P_CONTROL_HARD_RESET_SERVER_V1",
	3: "P_CONTROL_SOFT_RESET_V1",
	4: "P_CONTROL_V1",
	5: "P_ACK_V1",
	6: "P_DATA_V1",
	7: "P_CONTROL_HARD_RESET_CLIENT_V2",
	8: "P_CONTROL_HARD_RESET_SERVER_V2",
	9: "P_DATA_V2",
}

type parsedOpenVPN struct {
	Direction  string `json:"direction,omitempty"`
	Opcode     uint8  `json:"opcode,omitempty"`
	OpcodeName string `json:"opcode_name,omitempty"`
	KeyID      uint8  `json:"key_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
}

func parseOpenVPNHeader(data []byte) parsedOpenVPN {
	frame := parsedOpenVPN{Direction: "read", Payload: data}
	if len(data) == 0 {
		return frame
	}
	frame.Opcode = data[0] >> 3
	frame.KeyID = data[0] & 0x07
	if name, ok := openVPNOpcodeNames[frame.Opcode]; ok {
		frame.OpcodeName = name
	} else {
		frame.OpcodeName = "UNKNOWN"
	}
	if len(data) >= 9 {
		frame.SessionID = hex.EncodeToString(data[1:9])
	}
	return frame
}

// HandleOpenVPN parses an OpenVPN UDP datagram and emits one producer event
// with opcode / key_id / session_id tagged in decoded. It does not reply.
func HandleOpenVPN(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxOpenVPNPayload))
	copy(payload, data[:len(payload)])

	events := []parsedOpenVPN{}
	defer func() {
		if err := h.ProduceUDP("openvpn", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedOpenVPN](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "openvpn"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame := parseOpenVPNHeader(payload)
	events = append(events, frame)

	if len(payload) < 9 {
		logger.Debug("OpenVPN packet shorter than session header",
			slog.String("protocol", "openvpn"),
			slog.Int("bytes", len(payload)),
		)
	}

	logger.Info("OpenVPN UDP packet received",
		slog.String("handler", "openvpn"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("opcode", frame.OpcodeName),
		slog.Int("key_id", int(frame.KeyID)),
	)
	return nil
}
