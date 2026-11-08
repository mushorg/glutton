// Package stun parses STUN (RFC 5389/8489) messages and builds a
// coturn-like Binding Success Response.
package stun

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
)

const (
	// HeaderLen is the fixed STUN header length.
	HeaderLen = 20
	// MagicCookie is the RFC 5389 magic cookie at bytes 4-7.
	MagicCookie = 0x2112A442

	TypeBindingRequest = 0x0001
	TypeBindingSuccess = 0x0101

	attrMappedAddress    = 0x0001
	attrXORMappedAddress = 0x0020
)

var (
	errShort  = errors.New("stun: message shorter than header")
	errNotMsg = errors.New("stun: not a STUN message")
)

var methodNames = map[uint16]string{
	0x001: "binding",
	0x002: "shared-secret",
	0x003: "allocate",
	0x004: "refresh",
	0x006: "send",
	0x007: "data",
	0x008: "create-permission",
	0x009: "channel-bind",
	0x00a: "connect",
	0x00b: "connection-bind",
	0x00c: "connection-attempt",
}

var classNames = [4]string{"request", "indication", "success", "error"}

var attrNames = map[uint16]string{
	0x0001: "mapped-address",
	0x0002: "response-address",
	0x0003: "change-request",
	0x0004: "source-address",
	0x0005: "changed-address",
	0x0006: "username",
	0x0008: "message-integrity",
	0x0009: "error-code",
	0x000a: "unknown-attributes",
	0x000c: "channel-number",
	0x000d: "lifetime",
	0x0012: "xor-peer-address",
	0x0013: "data",
	0x0014: "realm",
	0x0015: "nonce",
	0x0016: "xor-relayed-address",
	0x0019: "requested-transport",
	0x001a: "dont-fragment",
	0x001c: "message-integrity-sha256",
	0x001e: "userhash",
	0x0020: "xor-mapped-address",
	0x0022: "reservation-token",
	0x0024: "priority",
	0x0025: "use-candidate",
	0x0026: "padding",
	0x0027: "response-port",
	0x8022: "software",
	0x8023: "alternate-server",
	0x8028: "fingerprint",
	0x8029: "ice-controlled",
	0x802a: "ice-controlling",
	0x802b: "response-origin",
	0x802c: "other-address",
}

// Message is a parsed STUN message.
type Message struct {
	Type          uint16
	TransactionID [12]byte
	Attributes    []string
	Software      string
}

// LooksLikeSTUN reports whether data is an RFC 5389 STUN message: top two
// bits zero, the magic cookie, and a 4-byte aligned length that matches the
// datagram.
func LooksLikeSTUN(data []byte) bool {
	if len(data) < HeaderLen || data[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != MagicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(data[2:4]))
	return n%4 == 0 && n == len(data)-HeaderLen
}

// Parse decodes the header and walks the attribute list.
func Parse(data []byte) (*Message, error) {
	if len(data) < HeaderLen {
		return nil, errShort
	}
	if !LooksLikeSTUN(data) {
		return nil, errNotMsg
	}
	m := &Message{Type: binary.BigEndian.Uint16(data[0:2])}
	copy(m.TransactionID[:], data[8:20])
	body := data[HeaderLen:]
	for len(body) >= 4 {
		t := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+l > len(body) {
			break
		}
		m.Attributes = append(m.Attributes, AttrName(t))
		if t == 0x8022 {
			m.Software = string(body[4 : 4+l])
		}
		adv := 4 + (l+3)&^3
		if adv > len(body) {
			break
		}
		body = body[adv:]
	}
	return m, nil
}

// Command returns "<method>-<class>", e.g. "binding-request".
func (m *Message) Command() string { return TypeName(m.Type) }

// TxID returns the transaction ID in hex.
func (m *Message) TxID() string { return hex.EncodeToString(m.TransactionID[:]) }

// TypeName names a STUN message type as "<method>-<class>".
func TypeName(t uint16) string {
	method := t&0x000F | (t>>1)&0x0070 | (t>>2)&0x0F80
	class := (t>>7)&0x2 | (t>>4)&0x1
	name, ok := methodNames[method]
	if !ok {
		name = fmt.Sprintf("method_%#x", method)
	}
	return name + "-" + classNames[class]
}

// AttrName names a STUN attribute type.
func AttrName(t uint16) string {
	if n, ok := attrNames[t]; ok {
		return n
	}
	return fmt.Sprintf("attr_%#04x", t)
}

// Software is the SOFTWARE attribute sent in Binding Success Responses. It
// matches the string coturn 4.6.x sends, the most common open STUN/TURN
// server on the Internet.
var Software = "Coturn-4.6.2 'Gorst'"

const (
	attrSoftware    = 0x8022
	attrFingerprint = 0x8028
	// fingerprintXOR is XORed into the CRC-32 (RFC 5389 §15.5).
	fingerprintXOR = 0x5354554e
)

// BuildBindingSuccess answers a Binding Request with a Binding Success
// Response for src in the attribute order coturn uses: XOR-MAPPED-ADDRESS,
// MAPPED-ADDRESS, SOFTWARE, FINGERPRINT. RESPONSE-ORIGIN is left out because
// it would carry the sensor's (possibly private) local address.
func BuildBindingSuccess(m *Message, src *net.UDPAddr) []byte {
	ip := src.IP.To4()
	family := byte(0x01)
	if ip == nil {
		ip = src.IP.To16()
		family = 0x02
	}
	if ip == nil {
		return nil
	}
	out := make([]byte, HeaderLen, 128)
	binary.BigEndian.PutUint16(out[0:2], TypeBindingSuccess)
	binary.BigEndian.PutUint32(out[4:8], MagicCookie)
	copy(out[8:20], m.TransactionID[:])

	key := out[4:20] // magic cookie followed by the transaction ID
	xorAddr := make([]byte, 4+len(ip))
	xorAddr[1] = family
	binary.BigEndian.PutUint16(xorAddr[2:4], uint16(src.Port)^uint16(MagicCookie>>16))
	for i, b := range ip {
		xorAddr[4+i] = b ^ key[i]
	}
	out = appendAttr(out, attrXORMappedAddress, xorAddr)

	addr := make([]byte, 4+len(ip))
	addr[1] = family
	binary.BigEndian.PutUint16(addr[2:4], uint16(src.Port))
	copy(addr[4:], ip)
	out = appendAttr(out, attrMappedAddress, addr)

	if Software != "" {
		out = appendAttr(out, attrSoftware, []byte(Software))
	}

	// the length field must already count FINGERPRINT when the CRC is taken
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-HeaderLen+8))
	crc := crc32.ChecksumIEEE(out) ^ fingerprintXOR
	out = appendAttr(out, attrFingerprint, binary.BigEndian.AppendUint32(nil, crc))
	return out
}

// appendAttr appends a TLV attribute padded to a 4-byte boundary.
func appendAttr(out []byte, t uint16, v []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, t)
	out = binary.BigEndian.AppendUint16(out, uint16(len(v)))
	out = append(out, v...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}
