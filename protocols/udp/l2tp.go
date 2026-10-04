package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxL2TPPayload = 1024

	l2tpFlagT      = 0x8000 // control message
	l2tpFlagL      = 0x4000 // length present
	l2tpFlagS      = 0x0800 // Ns/Nr present
	l2tpVerMask    = 0x000f
	l2tpAVPLenMask = 0x03ff

	// IETF AVP attribute types (RFC 2661).
	l2tpAttrMessageType      = 0
	l2tpAttrProtocolVersion  = 2
	l2tpAttrFramingCaps      = 3
	l2tpAttrBearerCaps       = 4
	l2tpAttrFirmwareRevision = 6
	l2tpAttrHostName         = 7
	l2tpAttrVendorName       = 8
	l2tpAttrAssignedTunnelID = 9

	l2tpMsgSCCRQ = 1
	l2tpMsgSCCRP = 2

	l2tpHoneypotTunnelID   = 0x0001
	l2tpHoneypotHostName   = "vpn"
	l2tpHoneypotVendorName = "linux"
)

var l2tpMessageNames = map[uint16]string{
	1:  "SCCRQ",
	2:  "SCCRP",
	3:  "SCCCN",
	4:  "StopCCN",
	6:  "HELLO",
	7:  "OCRQ",
	8:  "OCRP",
	9:  "OCCN",
	10: "ICRQ",
	11: "ICRP",
	12: "ICCN",
	14: "CDN",
	15: "WEN",
	16: "SLI",
}

type parsedL2TP struct {
	Direction        string `json:"direction,omitempty"`
	Command          string `json:"command,omitempty"`
	Status           string `json:"status,omitempty"`
	MessageType      uint16 `json:"message_type,omitempty"`
	MessageName      string `json:"message_name,omitempty"`
	HostName         string `json:"host_name,omitempty"`
	VendorName       string `json:"vendor_name,omitempty"`
	TunnelID         uint16 `json:"tunnel_id,omitempty"`
	AssignedTunnelID uint16 `json:"assigned_tunnel_id,omitempty"`
	Ns               uint16 `json:"ns,omitempty"`
	Nr               uint16 `json:"nr,omitempty"`
	Payload          []byte `json:"payload,omitempty"`
	Truncated        bool   `json:"truncated,omitempty"`
}

func l2tpMessageName(msgType uint16) string {
	if name, ok := l2tpMessageNames[msgType]; ok {
		return name
	}
	return "UNKNOWN"
}

func parseL2TP(data []byte) (parsedL2TP, error) {
	frame := parsedL2TP{Direction: "read", Payload: data}
	if len(data) < 2 {
		return frame, fmt.Errorf("shorter than L2TP flags")
	}

	flags := binary.BigEndian.Uint16(data[0:2])
	if flags&l2tpVerMask != 2 {
		return frame, fmt.Errorf("unsupported L2TP version %d", flags&l2tpVerMask)
	}
	if flags&l2tpFlagT == 0 {
		return frame, fmt.Errorf("not an L2TP control message")
	}

	off := 2
	if flags&l2tpFlagL != 0 {
		if len(data) < off+2 {
			return frame, fmt.Errorf("truncated L2TP length")
		}
		off += 2
	}
	if len(data) < off+4 {
		return frame, fmt.Errorf("truncated L2TP tunnel/session IDs")
	}
	frame.TunnelID = binary.BigEndian.Uint16(data[off : off+2])
	off += 4 // skip tunnel ID + session ID
	if flags&l2tpFlagS != 0 {
		if len(data) < off+4 {
			return frame, fmt.Errorf("truncated L2TP sequence numbers")
		}
		frame.Ns = binary.BigEndian.Uint16(data[off : off+2])
		frame.Nr = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}

	for off+6 <= len(data) {
		avpFlags := binary.BigEndian.Uint16(data[off : off+2])
		avpLen := int(avpFlags & l2tpAVPLenMask)
		if avpLen < 6 || off+avpLen > len(data) {
			return frame, fmt.Errorf("invalid AVP length %d at offset %d", avpLen, off)
		}
		vendor := binary.BigEndian.Uint16(data[off+2 : off+4])
		attr := binary.BigEndian.Uint16(data[off+4 : off+6])
		value := data[off+6 : off+avpLen]
		off += avpLen

		if vendor != 0 {
			continue
		}
		switch attr {
		case l2tpAttrMessageType:
			if len(value) >= 2 {
				frame.MessageType = binary.BigEndian.Uint16(value[:2])
				frame.MessageName = l2tpMessageName(frame.MessageType)
				frame.Command = frame.MessageName
			}
		case l2tpAttrHostName:
			frame.HostName = string(value)
		case l2tpAttrVendorName:
			frame.VendorName = string(value)
		case l2tpAttrAssignedTunnelID:
			if len(value) >= 2 {
				frame.AssignedTunnelID = binary.BigEndian.Uint16(value[:2])
			}
		}
	}
	if frame.MessageType == 0 && frame.MessageName == "" {
		return frame, fmt.Errorf("missing Message Type AVP")
	}
	return frame, nil
}

func encodeL2TPAVP(mandatory bool, attr uint16, value []byte) []byte {
	length := 6 + len(value)
	flags := uint16(length) & l2tpAVPLenMask
	if mandatory {
		flags |= 0x8000
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[0:2], flags)
	binary.BigEndian.PutUint16(out[4:6], attr)
	copy(out[6:], value)
	return out
}

// buildSCCRP builds an RFC 2661 Start-Control-Connection-Reply that scanners
// (nmap -sU -sV and internet-wide L2TP probes) treat as evidence of an LNS.
func buildSCCRP(peerAssignedTID, peerNs uint16) []byte {
	u16 := func(v uint16) []byte {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, v)
		return b
	}
	u32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}

	avps := append([]byte{}, encodeL2TPAVP(true, l2tpAttrMessageType, u16(l2tpMsgSCCRP))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrProtocolVersion, []byte{0x01, 0x00})...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrFramingCaps, u32(3))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrBearerCaps, u32(3))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrHostName, []byte(l2tpHoneypotHostName))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrAssignedTunnelID, u16(l2tpHoneypotTunnelID))...)
	avps = append(avps, encodeL2TPAVP(false, l2tpAttrFirmwareRevision, u16(1))...)
	avps = append(avps, encodeL2TPAVP(false, l2tpAttrVendorName, []byte(l2tpHoneypotVendorName))...)

	total := 12 + len(avps)
	out := make([]byte, total)
	binary.BigEndian.PutUint16(out[0:2], l2tpFlagT|l2tpFlagL|l2tpFlagS|2)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	binary.BigEndian.PutUint16(out[4:6], peerAssignedTID) // peer's Assigned Tunnel ID
	// session ID stays 0
	binary.BigEndian.PutUint16(out[8:10], 0)         // Ns
	binary.BigEndian.PutUint16(out[10:12], peerNs+1) // Nr
	copy(out[12:], avps)
	return out
}

// HandleL2TP parses an L2TP UDP datagram, answers SCCRQ with SCCRP, and emits
// one producer event with message type / host / vendor tagged in decoded.
func HandleL2TP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxL2TPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedL2TP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("l2tp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedL2TP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame, err := parseL2TP(payload)
	frame.Truncated = len(data) > maxL2TPPayload
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse L2TP control message",
			slog.String("protocol", "l2tp"),
			producer.ErrAttr(err),
			slog.Int("bytes", len(payload)),
		)
		return nil
	}

	logger.Info("L2TP UDP packet received",
		slog.String("handler", "l2tp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("message", frame.MessageName),
		slog.String("host_name", frame.HostName),
		slog.String("vendor_name", frame.VendorName),
	)

	if frame.MessageType != l2tpMsgSCCRQ {
		return nil
	}

	resp := buildSCCRP(frame.AssignedTunnelID, frame.Ns)
	events = append(events, parsedL2TP{
		Direction:        "write",
		Command:          l2tpMessageName(l2tpMsgSCCRP),
		Status:           "SCCRP",
		MessageType:      l2tpMsgSCCRP,
		MessageName:      l2tpMessageName(l2tpMsgSCCRP),
		HostName:         l2tpHoneypotHostName,
		VendorName:       l2tpHoneypotVendorName,
		TunnelID:         frame.AssignedTunnelID,
		AssignedTunnelID: l2tpHoneypotTunnelID,
		Ns:               0,
		Nr:               frame.Ns + 1,
		Payload:          resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to reply to L2TP SCCRQ", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return err
	}
	return nil
}
