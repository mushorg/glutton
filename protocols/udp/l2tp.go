package udp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	l2tpproto "github.com/mushorg/glutton/protocols/udp/l2tp"
)

const (
	maxL2TPPayload = 1024

	l2tpFlagT      = 0x8000 // control message
	l2tpFlagL      = 0x4000 // length present
	l2tpFlagS      = 0x0800 // Ns/Nr present
	l2tpVerMask    = 0x000f
	l2tpAVPLenMask = 0x03ff

	// IETF AVP attribute types (RFC 2661).
	l2tpAttrMessageType       = 0
	l2tpAttrProtocolVersion   = 2
	l2tpAttrFramingCaps       = 3
	l2tpAttrBearerCaps        = 4
	l2tpAttrFirmwareRevision  = 6
	l2tpAttrHostName          = 7
	l2tpAttrVendorName        = 8
	l2tpAttrAssignedTunnelID  = 9
	l2tpAttrAssignedSessionID = 14

	l2tpMsgSCCRQ   = 1
	l2tpMsgSCCRP   = 2
	l2tpMsgSCCCN   = 3
	l2tpMsgStopCCN = 4
	l2tpMsgHELLO   = 6
	l2tpMsgICRQ    = 10
	l2tpMsgICRP    = 11
	l2tpMsgICCN    = 12
	l2tpMsgCDN     = 14

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
	Direction         string `json:"direction,omitempty"`
	Command           string `json:"command,omitempty"`
	Status            string `json:"status,omitempty"`
	MessageType       uint16 `json:"message_type,omitempty"`
	MessageName       string `json:"message_name,omitempty"`
	HostName          string `json:"host_name,omitempty"`
	VendorName        string `json:"vendor_name,omitempty"`
	TunnelID          uint16 `json:"tunnel_id,omitempty"`
	SessionID         uint16 `json:"session_id,omitempty"`
	AssignedTunnelID  uint16 `json:"assigned_tunnel_id,omitempty"`
	AssignedSessionID uint16 `json:"assigned_session_id,omitempty"`
	Ns                uint16 `json:"ns,omitempty"`
	Nr                uint16 `json:"nr,omitempty"`
	// PPP inside data messages
	PPPProtocol  string `json:"ppp_protocol,omitempty"`  // LCP, PAP, CHAP
	AuthProtocol string `json:"auth_protocol,omitempty"` // PAP, CHAP-MD5, MS-CHAPv2
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	CHAPResponse string `json:"chap_response,omitempty"` // hex CHAP Response value
	Payload      []byte `json:"payload,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
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
	frame.SessionID = binary.BigEndian.Uint16(data[off+2 : off+4])
	off += 4
	if flags&l2tpFlagS != 0 {
		if len(data) < off+4 {
			return frame, fmt.Errorf("truncated L2TP sequence numbers")
		}
		frame.Ns = binary.BigEndian.Uint16(data[off : off+2])
		frame.Nr = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}
	if off == len(data) {
		// Zero-Length Body: a bare acknowledgement
		frame.MessageName = "ZLB"
		frame.Command = "ZLB"
		return frame, nil
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
		case l2tpAttrAssignedSessionID:
			if len(value) >= 2 {
				frame.AssignedSessionID = binary.BigEndian.Uint16(value[:2])
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

func l2tpU16(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}

// buildL2TPControl frames AVPs as a control message; with no AVPs it is a
// ZLB acknowledgement.
func buildL2TPControl(tunnelID, sessionID, ns, nr uint16, avps []byte) []byte {
	total := 12 + len(avps)
	out := make([]byte, total)
	binary.BigEndian.PutUint16(out[0:2], l2tpFlagT|l2tpFlagL|l2tpFlagS|2)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	binary.BigEndian.PutUint16(out[4:6], tunnelID)
	binary.BigEndian.PutUint16(out[6:8], sessionID)
	binary.BigEndian.PutUint16(out[8:10], ns)
	binary.BigEndian.PutUint16(out[10:12], nr)
	copy(out[12:], avps)
	return out
}

// buildSCCRP builds an RFC 2661 Start-Control-Connection-Reply that scanners
// (nmap -sU -sV and internet-wide L2TP probes) treat as evidence of an LNS.
// peerTID is the client's Assigned Tunnel ID, localTID the honeypot's.
func buildSCCRP(peerTID, localTID, ns, nr uint16) []byte {
	avps := encodeL2TPAVP(true, l2tpAttrMessageType, l2tpU16(l2tpMsgSCCRP))
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrProtocolVersion, []byte{0x01, 0x00})...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrFramingCaps, binary.BigEndian.AppendUint32(nil, 3))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrBearerCaps, binary.BigEndian.AppendUint32(nil, 3))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrHostName, []byte(l2tpHoneypotHostName))...)
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrAssignedTunnelID, l2tpU16(localTID))...)
	avps = append(avps, encodeL2TPAVP(false, l2tpAttrFirmwareRevision, l2tpU16(1))...)
	avps = append(avps, encodeL2TPAVP(false, l2tpAttrVendorName, []byte(l2tpHoneypotVendorName))...)
	return buildL2TPControl(peerTID, 0, ns, nr, avps)
}

// buildICRP builds an Incoming-Call-Reply assigning the honeypot's session ID.
func buildICRP(peerTID, peerSID, localSID, ns, nr uint16) []byte {
	avps := encodeL2TPAVP(true, l2tpAttrMessageType, l2tpU16(l2tpMsgICRP))
	avps = append(avps, encodeL2TPAVP(true, l2tpAttrAssignedSessionID, l2tpU16(localSID))...)
	return buildL2TPControl(peerTID, peerSID, ns, nr, avps)
}

// HandleL2TP handles one L2TP UDP datagram. An SCCRQ opens a tunnel that
// collects the control connection, its sessions and the PPP negotiation
// (including PAP/CHAP attempts) into one event; datagrams that match no
// tunnel are produced on their own.
func HandleL2TP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxL2TPPayload))
	copy(payload, data[:len(payload)])
	truncated := len(data) > maxL2TPPayload

	if len(payload) == 0 {
		return produceL2TPDatagram(srcAddr, dstAddr, md, logger, h, nil)
	}

	if len(payload) >= 2 && binary.BigEndian.Uint16(payload[0:2])&l2tpFlagT == 0 {
		frame, hdr, pkt, err := parseL2TPData(payload)
		frame.Truncated = truncated
		if err == nil {
			if t := l2tpTunnels.get(l2tpTunnelKey(srcAddr, hdr.TunnelID)); t != nil {
				if handled, err := t.handleData(frame, hdr, pkt); handled {
					return err
				}
			}
		} else {
			logger.Debug("Failed to parse L2TP data message", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
		}
		return produceL2TPDatagram(srcAddr, dstAddr, md, logger, h, []parsedL2TP{frame})
	}

	frame, err := parseL2TP(payload)
	frame.Truncated = truncated
	if err != nil {
		logger.Debug("Failed to parse L2TP control message",
			slog.String("protocol", "l2tp"),
			producer.ErrAttr(err),
			slog.Int("bytes", len(payload)),
		)
		return produceL2TPDatagram(srcAddr, dstAddr, md, logger, h, []parsedL2TP{frame})
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

	if frame.MessageType == l2tpMsgSCCRQ && frame.TunnelID == 0 {
		return openL2TPTunnel(ctx, srcAddr, dstAddr, md, logger, h, frame)
	}
	if t := l2tpTunnels.get(l2tpTunnelKey(srcAddr, frame.TunnelID)); t != nil {
		if handled, err := t.handleControl(frame); handled {
			return err
		}
	}
	return produceL2TPDatagram(srcAddr, dstAddr, md, logger, h, []parsedL2TP{frame})
}

// produceL2TPDatagram emits a datagram that belongs to no tunnel as its own
// event, without replying.
func produceL2TPDatagram(srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, events []parsedL2TP) error {
	if events == nil {
		events = []parsedL2TP{}
	}
	md.EndReason = connection.EndHandlerClose
	if err := h.ProduceUDP("l2tp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedL2TP](events).Payload, events); err != nil {
		logger.Error("Failed to produce message", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
	}
	return nil
}

// parseL2TPData parses a data message and the PPP control packet it carries.
func parseL2TPData(data []byte) (parsedL2TP, l2tpproto.DataHeader, l2tpproto.Packet, error) {
	frame := parsedL2TP{Direction: "read", Payload: data}
	hdr, ppp, err := l2tpproto.ParseData(data)
	if err != nil {
		return frame, hdr, l2tpproto.Packet{}, err
	}
	frame.TunnelID = hdr.TunnelID
	frame.SessionID = hdr.SessionID
	frame.Ns, frame.Nr = hdr.Ns, hdr.Nr
	pkt, err := l2tpproto.ParsePPP(ppp)
	if pkt.Protocol != 0 {
		frame.PPPProtocol = l2tpproto.ProtocolName(pkt.Protocol)
	}
	if err != nil {
		return frame, hdr, pkt, err
	}
	frame.Command = l2tpproto.Command(pkt.Protocol, pkt.Code)
	switch {
	case pkt.Protocol == l2tpproto.ProtoPAP && pkt.Code == l2tpproto.CodePAPAuthRequest:
		frame.AuthProtocol = "PAP"
		frame.Username, frame.Password, err = l2tpproto.ParsePAPRequest(pkt.Data)
	case pkt.Protocol == l2tpproto.ProtoCHAP && pkt.Code == l2tpproto.CodeCHAPResponse:
		var value []byte
		value, frame.Username, err = l2tpproto.ParseCHAPResponse(pkt.Data)
		frame.CHAPResponse = hex.EncodeToString(value)
	case pkt.Protocol == l2tpproto.ProtoLCP && pkt.Code <= l2tpproto.CodeConfigureReject:
		if opts, perr := l2tpproto.ParseOptions(pkt.Data); perr == nil {
			if proto, alg, ok := l2tpproto.AuthOption(opts); ok {
				frame.AuthProtocol = l2tpproto.AuthName(proto, alg)
			}
		}
	}
	return frame, hdr, pkt, err
}
