// Package l2tp parses and builds the PPP frames an L2TP v2 session carries
// in data messages (RFC 2661 §3.1, RFC 1661 LCP, RFC 1334 PAP, RFC 1994 CHAP).
package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	flagT      = 0x8000
	flagL      = 0x4000
	flagS      = 0x0800
	flagO      = 0x0200
	versionMax = 0x000f

	ProtoLCP  = 0xc021
	ProtoPAP  = 0xc023
	ProtoCHAP = 0xc223

	// LCP / PAP / CHAP codes
	CodeConfigureRequest = 1
	CodeConfigureAck     = 2
	CodeConfigureNak     = 3
	CodeConfigureReject  = 4
	CodeTerminateRequest = 5
	CodeTerminateAck     = 6
	CodeEchoRequest      = 9
	CodeEchoReply        = 10

	CodePAPAuthRequest = 1
	CodePAPAuthAck     = 2
	CodePAPAuthNak     = 3

	CodeCHAPChallenge = 1
	CodeCHAPResponse  = 2
	CodeCHAPSuccess   = 3
	CodeCHAPFailure   = 4

	// LCP option types
	OptAuthProtocol = 3
	OptMagicNumber  = 5

	CHAPMD5      = 0x05
	CHAPMSCHAPv2 = 0x81
)

var protoNames = map[uint16]string{ProtoLCP: "LCP", ProtoPAP: "PAP", ProtoCHAP: "CHAP"}

var codeNames = map[uint16]map[uint8]string{
	ProtoLCP: {
		1: "Configure-Request", 2: "Configure-Ack", 3: "Configure-Nak", 4: "Configure-Reject",
		5: "Terminate-Request", 6: "Terminate-Ack", 7: "Code-Reject", 8: "Protocol-Reject",
		9: "Echo-Request", 10: "Echo-Reply", 11: "Discard-Request",
	},
	ProtoPAP:  {1: "Authenticate-Request", 2: "Authenticate-Ack", 3: "Authenticate-Nak"},
	ProtoCHAP: {1: "Challenge", 2: "Response", 3: "Success", 4: "Failure"},
}

// ProtocolName names a PPP protocol number, or formats it as hex.
func ProtocolName(proto uint16) string {
	if name, ok := protoNames[proto]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", proto)
}

// Command is "<protocol> <code name>", e.g. "PAP Authenticate-Request".
func Command(proto uint16, code uint8) string {
	if name, ok := codeNames[proto][code]; ok {
		return ProtocolName(proto) + " " + name
	}
	return fmt.Sprintf("%s code-%d", ProtocolName(proto), code)
}

// AuthName names an LCP Authentication-Protocol option value.
func AuthName(proto uint16, algorithm uint8) string {
	switch {
	case proto == ProtoPAP:
		return "PAP"
	case proto == ProtoCHAP && algorithm == CHAPMD5:
		return "CHAP-MD5"
	case proto == ProtoCHAP && algorithm == CHAPMSCHAPv2:
		return "MS-CHAPv2"
	case proto == ProtoCHAP:
		return fmt.Sprintf("CHAP-0x%02x", algorithm)
	}
	return ProtocolName(proto)
}

// DataHeader is the header of an L2TP data message (T bit clear).
type DataHeader struct {
	TunnelID  uint16
	SessionID uint16
	Ns, Nr    uint16
}

// ParseData splits an L2TP v2 data message into its header and PPP frame.
func ParseData(b []byte) (DataHeader, []byte, error) {
	var hdr DataHeader
	if len(b) < 6 {
		return hdr, nil, errors.New("short L2TP data message")
	}
	flags := binary.BigEndian.Uint16(b[0:2])
	if flags&flagT != 0 {
		return hdr, nil, errors.New("not an L2TP data message")
	}
	if flags&versionMax != 2 {
		return hdr, nil, fmt.Errorf("unsupported L2TP version %d", flags&versionMax)
	}
	off := 2
	end := len(b)
	if flags&flagL != 0 {
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if l < 8 || l > len(b) {
			return hdr, nil, fmt.Errorf("invalid L2TP length %d", l)
		}
		end = l
		off += 2
	}
	if end < off+4 {
		return hdr, nil, errors.New("truncated L2TP tunnel/session IDs")
	}
	hdr.TunnelID = binary.BigEndian.Uint16(b[off : off+2])
	hdr.SessionID = binary.BigEndian.Uint16(b[off+2 : off+4])
	off += 4
	if flags&flagS != 0 {
		if end < off+4 {
			return hdr, nil, errors.New("truncated L2TP sequence numbers")
		}
		hdr.Ns = binary.BigEndian.Uint16(b[off : off+2])
		hdr.Nr = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if flags&flagO != 0 {
		if end < off+2 {
			return hdr, nil, errors.New("truncated L2TP offset size")
		}
		pad := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2 + pad
		if off > end {
			return hdr, nil, errors.New("L2TP offset past end of message")
		}
	}
	return hdr, b[off:end], nil
}

// BuildData wraps a PPP frame in an L2TP v2 data message without length or
// sequence fields, as LNS implementations commonly send them.
func BuildData(tunnelID, sessionID uint16, ppp []byte) []byte {
	out := make([]byte, 6+len(ppp))
	binary.BigEndian.PutUint16(out[0:2], 2)
	binary.BigEndian.PutUint16(out[2:4], tunnelID)
	binary.BigEndian.PutUint16(out[4:6], sessionID)
	copy(out[6:], ppp)
	return out
}

// Packet is one LCP/PAP/CHAP packet inside a PPP frame.
type Packet struct {
	Protocol uint16
	Code     uint8
	ID       uint8
	Data     []byte // bytes after the 4-byte code/id/length header
	// ACF is set when the frame carried the 0xff 0x03 address/control
	// field; replies mirror it.
	ACF bool
}

// ParsePPP parses a PPP frame (HDLC address/control field optional, protocol
// field compressed or not) carrying an LCP, PAP or CHAP packet.
func ParsePPP(b []byte) (Packet, error) {
	var p Packet
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0x03 {
		p.ACF = true
		b = b[2:]
	}
	if len(b) < 1 {
		return p, errors.New("empty PPP frame")
	}
	if b[0]&1 == 1 {
		p.Protocol = uint16(b[0])
		b = b[1:]
	} else {
		if len(b) < 2 {
			return p, errors.New("truncated PPP protocol")
		}
		p.Protocol = binary.BigEndian.Uint16(b[0:2])
		b = b[2:]
	}
	if _, ok := protoNames[p.Protocol]; !ok {
		return p, fmt.Errorf("unhandled PPP protocol %s", ProtocolName(p.Protocol))
	}
	if len(b) < 4 {
		return p, errors.New("truncated PPP control packet")
	}
	p.Code = b[0]
	p.ID = b[1]
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l < 4 || l > len(b) {
		return p, fmt.Errorf("invalid PPP packet length %d", l)
	}
	p.Data = b[4:l]
	return p, nil
}

// BuildPPP encodes a control packet as a PPP frame.
func BuildPPP(acf bool, proto uint16, code, id uint8, data []byte) []byte {
	out := make([]byte, 0, 8+len(data))
	if acf {
		out = append(out, 0xff, 0x03)
	}
	out = binary.BigEndian.AppendUint16(out, proto)
	out = append(out, code, id)
	out = binary.BigEndian.AppendUint16(out, uint16(4+len(data)))
	return append(out, data...)
}

// Option is one LCP configuration option.
type Option struct {
	Type uint8
	Data []byte
}

// ParseOptions parses the options of an LCP Configure-* packet.
func ParseOptions(b []byte) ([]Option, error) {
	var opts []Option
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return opts, errors.New("invalid LCP option")
		}
		opts = append(opts, Option{Type: b[0], Data: b[2:b[1]]})
		b = b[b[1]:]
	}
	return opts, nil
}

// AuthOption returns the Authentication-Protocol option of opts.
func AuthOption(opts []Option) (proto uint16, algorithm uint8, ok bool) {
	for _, o := range opts {
		if o.Type == OptAuthProtocol && len(o.Data) >= 2 {
			proto = binary.BigEndian.Uint16(o.Data[0:2])
			if len(o.Data) >= 3 {
				algorithm = o.Data[2]
			}
			return proto, algorithm, true
		}
	}
	return 0, 0, false
}

// MagicNumber returns the Magic-Number option of opts.
func MagicNumber(opts []Option) (uint32, bool) {
	for _, o := range opts {
		if o.Type == OptMagicNumber && len(o.Data) == 4 {
			return binary.BigEndian.Uint32(o.Data), true
		}
	}
	return 0, false
}

// ConfigureRequestOptions builds the options of the LNS's LCP
// Configure-Request: the authentication protocol it demands and its magic
// number.
func ConfigureRequestOptions(authProto uint16, algorithm uint8, magic uint32) []byte {
	var out []byte
	if authProto == ProtoCHAP {
		out = append(out, OptAuthProtocol, 5, byte(ProtoCHAP>>8), byte(ProtoCHAP&0xff), algorithm)
	} else {
		out = append(out, OptAuthProtocol, 4, byte(ProtoPAP>>8), byte(ProtoPAP&0xff))
	}
	out = append(out, OptMagicNumber, 6)
	return binary.BigEndian.AppendUint32(out, magic)
}

// ParsePAPRequest returns the peer ID and password of a PAP
// Authenticate-Request.
func ParsePAPRequest(data []byte) (string, string, error) {
	if len(data) < 1 || int(data[0])+1 > len(data) {
		return "", "", errors.New("truncated PAP peer ID")
	}
	user := string(data[1 : 1+data[0]])
	rest := data[1+data[0]:]
	if len(rest) < 1 || int(rest[0])+1 > len(rest) {
		return user, "", errors.New("truncated PAP password")
	}
	return user, string(rest[1 : 1+rest[0]]), nil
}

// PAPMessage builds the data of a PAP Authenticate-Ack/Nak.
func PAPMessage(msg string) []byte {
	if len(msg) > 255 {
		msg = msg[:255]
	}
	return append([]byte{byte(len(msg))}, msg...)
}

// CHAPChallenge builds the data of a CHAP Challenge.
func CHAPChallenge(value []byte, name string) []byte {
	out := append([]byte{byte(len(value))}, value...)
	return append(out, name...)
}

// ParseCHAPResponse returns the value and name of a CHAP Response.
func ParseCHAPResponse(data []byte) ([]byte, string, error) {
	if len(data) < 1 || int(data[0])+1 > len(data) {
		return nil, "", errors.New("truncated CHAP response value")
	}
	n := int(data[0])
	return data[1 : 1+n], string(data[1+n:]), nil
}
