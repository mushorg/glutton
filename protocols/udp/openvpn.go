package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/spf13/viper"
)

const (
	maxOpenVPNPayload = 1024

	openVPNOpHardResetClientV1 = 1
	openVPNOpHardResetClientV2 = 7
	openVPNOpHardResetServerV2 = 8

	// opcode/key_id byte, session ID, ack array length
	openVPNHeaderLen = 1 + 8 + 1
)

// openVPNRandRead fills the server session ID; tests swap it.
var openVPNRandRead = rand.Read

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
	Direction  string  `json:"direction,omitempty"`
	Command    string  `json:"command,omitempty"`
	Opcode     uint8   `json:"opcode,omitempty"`
	OpcodeName string  `json:"opcode_name,omitempty"`
	KeyID      uint8   `json:"key_id,omitempty"`
	SessionID  string  `json:"session_id,omitempty"`
	AckCount   int     `json:"ack_count,omitempty"`
	PacketID   *uint32 `json:"packet_id,omitempty"`
	Malformed  bool    `json:"malformed,omitempty"` // client reset too short for ack array and packet ID
	Status     string  `json:"status,omitempty"`    // write outcome
	Payload    []byte  `json:"payload,omitempty"`
	Truncated  bool    `json:"truncated,omitempty"`
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
	frame.Command = frame.OpcodeName
	if len(data) >= 9 {
		frame.SessionID = hex.EncodeToString(data[1:9])
	}
	if frame.Opcode == openVPNOpHardResetClientV1 || frame.Opcode == openVPNOpHardResetClientV2 {
		parseOpenVPNReset(&frame, data)
	}
	return frame
}

// parseOpenVPNReset reads the ack array and message packet ID of a client
// hard reset: opcode, session ID, ack count, acks (4 bytes each, followed by
// the peer's 8-byte session ID when any), packet ID.
func parseOpenVPNReset(frame *parsedOpenVPN, data []byte) {
	if len(data) < openVPNHeaderLen {
		frame.Malformed = true
		return
	}
	acks := int(data[9])
	rest := data[openVPNHeaderLen:]
	if acks > 0 {
		need := acks*4 + 8
		if len(rest) < need {
			frame.AckCount = acks
			frame.Malformed = true
			return
		}
		rest = rest[need:]
	}
	frame.AckCount = acks
	if len(rest) < 4 {
		frame.Malformed = true
		return
	}
	id := binary.BigEndian.Uint32(rest[:4])
	frame.PacketID = &id
}

// openVPNHardResetServer builds a P_CONTROL_HARD_RESET_SERVER_V2 (no
// tls-auth/tls-crypt) acking the client's reset.
func openVPNHardResetServer(client parsedOpenVPN, clientSession []byte) ([]byte, []byte, error) {
	serverSession := make([]byte, 8)
	if _, err := openVPNRandRead(serverSession); err != nil {
		return nil, nil, err
	}
	out := make([]byte, 0, 1+8+1+4+8+4)
	out = append(out, openVPNOpHardResetServerV2<<3|client.KeyID)
	out = append(out, serverSession...)
	out = append(out, 1)
	out = binary.BigEndian.AppendUint32(out, *client.PacketID)
	out = append(out, clientSession...)
	out = binary.BigEndian.AppendUint32(out, 0)
	return out, serverSession, nil
}

// HandleOpenVPN parses an OpenVPN UDP datagram and emits one producer event
// with opcode / key_id / session_id tagged in decoded. It replies to a
// well-formed client hard reset only when openvpn.reply is true.
func HandleOpenVPN(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxOpenVPNPayload))
	copy(payload, data[:len(payload)])

	events := []parsedOpenVPN{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("openvpn", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedOpenVPN](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "openvpn"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame := parseOpenVPNHeader(payload)
	frame.Truncated = len(data) > maxOpenVPNPayload
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

	if !viper.GetBool("openvpn.reply") || frame.Opcode != openVPNOpHardResetClientV2 || frame.PacketID == nil {
		return nil
	}
	resp, serverSession, err := openVPNHardResetServer(frame, payload[1:9])
	if err != nil {
		logger.Error("Failed to build OpenVPN reply", slog.String("protocol", "openvpn"), producer.ErrAttr(err))
		return err
	}
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send OpenVPN reply", slog.String("protocol", "openvpn"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return err
	}
	zero := uint32(0)
	name := openVPNOpcodeNames[openVPNOpHardResetServerV2]
	events = append(events, parsedOpenVPN{
		Direction:  "write",
		Command:    name,
		Opcode:     openVPNOpHardResetServerV2,
		OpcodeName: name,
		KeyID:      frame.KeyID,
		SessionID:  hex.EncodeToString(serverSession),
		AckCount:   1,
		PacketID:   &zero,
		Status:     "ok",
		Payload:    resp,
	})
	return nil
}
