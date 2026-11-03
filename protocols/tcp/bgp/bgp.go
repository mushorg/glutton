// Package bgp holds the byte-level BGP-4 (RFC 4271) framing used by the bgp
// handler: header validation, OPEN parsing and the OPEN, KEEPALIVE and
// NOTIFICATION messages the honeypot sends back.
package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// HeaderLen is the fixed BGP header: 16-byte marker, 2-byte length, 1-byte type.
	HeaderLen = 19
	// MaxLen is the largest message RFC 4271 allows.
	MaxLen = 4096
	// Version is the only BGP version spoken.
	Version = 4

	minOpenLen         = 29
	minUpdateLen       = 23
	minNotificationLen = 21
	minRouteRefreshLen = 23
)

// Message types (RFC 4271 §4.1, RFC 2918 for ROUTE-REFRESH).
const (
	TypeOpen         uint8 = 1
	TypeUpdate       uint8 = 2
	TypeNotification uint8 = 3
	TypeKeepalive    uint8 = 4
	TypeRouteRefresh uint8 = 5
)

// NOTIFICATION error codes and the subcodes used here (RFC 4271 §4.5, §6).
const (
	ErrCodeHeader uint8 = 1
	ErrCodeOpen   uint8 = 2
	ErrCodeFSM    uint8 = 5
	ErrCodeCease  uint8 = 6

	SubConnectionNotSynchronized uint8 = 1
	SubBadMessageLength          uint8 = 2
	SubBadMessageType            uint8 = 3

	SubUnsupportedVersion   uint8 = 1
	SubUnacceptableHoldTime uint8 = 6
)

// Capability codes advertised in the honeypot's OPEN.
const (
	CapMultiprotocol uint8 = 1
	CapRouteRefresh  uint8 = 2
	CapFourOctetAS   uint8 = 65
)

const optParamCapabilities = 2

// Header is the parsed fixed header (the marker is validated, not stored).
type Header struct {
	Length uint16 `json:"length"`
	Type   uint8  `json:"type"`
}

// Open is the parsed body of an OPEN message.
type Open struct {
	Version      uint8   `json:"version"`
	AS           uint16  `json:"as"`
	HoldTime     uint16  `json:"hold_time"`
	BGPID        string  `json:"bgp_id"`
	OptParamsLen uint8   `json:"opt_params_len,omitempty"`
	Capabilities []uint8 `json:"capabilities,omitempty"`
	AS4          uint32  `json:"as4,omitempty"` // from the four-octet AS capability
}

// Notification is the parsed body of a NOTIFICATION message.
type Notification struct {
	Code    uint8  `json:"code"`
	Subcode uint8  `json:"subcode"`
	Data    []byte `json:"data,omitempty"`
}

// HeaderError is a header violation that must be answered with a Message
// Header Error NOTIFICATION carrying Subcode and Data.
type HeaderError struct {
	Subcode uint8
	Data    []byte
	msg     string
}

func (e *HeaderError) Error() string { return e.msg }

// ErrShortOpen is returned for an OPEN body shorter than its fixed fields or
// its declared optional parameters.
var ErrShortOpen = errors.New("bgp: OPEN body too short")

// TypeName names a message type the way it appears in `command`.
func TypeName(t uint8) string {
	switch t {
	case TypeOpen:
		return "OPEN"
	case TypeUpdate:
		return "UPDATE"
	case TypeNotification:
		return "NOTIFICATION"
	case TypeKeepalive:
		return "KEEPALIVE"
	case TypeRouteRefresh:
		return "ROUTE-REFRESH"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

// ReadMessage reads one BGP message. raw holds every byte consumed, so a
// partial header or a rejected header is still returned for recording. A
// *HeaderError means the header was invalid and the body was not read.
func ReadMessage(r io.Reader) (Header, []byte, error) {
	hdr := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return Header{}, hdr[:n], err
	}
	h, err := ParseHeader(hdr)
	if err != nil {
		return h, hdr, err
	}
	raw := make([]byte, h.Length)
	copy(raw, hdr)
	n, err = io.ReadFull(r, raw[HeaderLen:])
	if err != nil {
		return h, raw[:HeaderLen+n], err
	}
	return h, raw, nil
}

// ParseHeader validates the marker, length and type of a 19-byte header in
// the order RFC 4271 §6.1 checks them.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, io.ErrUnexpectedEOF
	}
	for _, c := range b[:16] {
		if c != 0xff {
			return Header{}, &HeaderError{Subcode: SubConnectionNotSynchronized, msg: "bgp: marker not all ones"}
		}
	}
	h := Header{Length: binary.BigEndian.Uint16(b[16:18]), Type: b[18]}
	lenData := []byte{b[16], b[17]}
	if h.Length < HeaderLen || h.Length > MaxLen {
		return h, &HeaderError{Subcode: SubBadMessageLength, Data: lenData, msg: fmt.Sprintf("bgp: bad message length %d", h.Length)}
	}
	var minLen uint16
	switch h.Type {
	case TypeOpen:
		minLen = minOpenLen
	case TypeUpdate:
		minLen = minUpdateLen
	case TypeNotification:
		minLen = minNotificationLen
	case TypeKeepalive:
		if h.Length != HeaderLen {
			return h, &HeaderError{Subcode: SubBadMessageLength, Data: lenData, msg: fmt.Sprintf("bgp: bad KEEPALIVE length %d", h.Length)}
		}
	case TypeRouteRefresh:
		minLen = minRouteRefreshLen
	default:
		return h, &HeaderError{Subcode: SubBadMessageType, Data: []byte{h.Type}, msg: fmt.Sprintf("bgp: bad message type %d", h.Type)}
	}
	if h.Length < minLen {
		return h, &HeaderError{Subcode: SubBadMessageLength, Data: lenData, msg: fmt.Sprintf("bgp: %s too short (%d)", TypeName(h.Type), h.Length)}
	}
	return h, nil
}

// ParseOpen parses an OPEN body (the bytes after the header).
func ParseOpen(body []byte) (Open, error) {
	if len(body) < minOpenLen-HeaderLen {
		return Open{}, ErrShortOpen
	}
	o := Open{
		Version:      body[0],
		AS:           binary.BigEndian.Uint16(body[1:3]),
		HoldTime:     binary.BigEndian.Uint16(body[3:5]),
		BGPID:        net.IP(body[5:9]).String(),
		OptParamsLen: body[9],
	}
	params := body[10:]
	if int(o.OptParamsLen) > len(params) {
		return o, ErrShortOpen
	}
	params = params[:o.OptParamsLen]
	for len(params) >= 2 {
		ptype, plen := params[0], int(params[1])
		if 2+plen > len(params) {
			return o, ErrShortOpen
		}
		if ptype == optParamCapabilities {
			caps := params[2 : 2+plen]
			for len(caps) >= 2 {
				code, clen := caps[0], int(caps[1])
				if 2+clen > len(caps) {
					break
				}
				o.Capabilities = append(o.Capabilities, code)
				if code == CapFourOctetAS && clen == 4 {
					o.AS4 = binary.BigEndian.Uint32(caps[2:6])
				}
				caps = caps[2+clen:]
			}
		}
		params = params[2+plen:]
	}
	return o, nil
}

// ParseNotification parses a NOTIFICATION body.
func ParseNotification(body []byte) (Notification, bool) {
	if len(body) < 2 {
		return Notification{}, false
	}
	return Notification{Code: body[0], Subcode: body[1], Data: body[2:]}, true
}

func build(t uint8, body []byte) []byte {
	msg := make([]byte, HeaderLen+len(body))
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(len(msg)))
	msg[18] = t
	copy(msg[HeaderLen:], body)
	return msg
}

// BuildOpen builds an OPEN advertising IPv4 unicast, route refresh and the
// four-octet AS capability, as a typical router does.
func BuildOpen(as uint16, holdTime uint16, bgpID [4]byte) []byte {
	caps := []byte{
		CapMultiprotocol, 4, 0, 1, 0, 1, // AFI IPv4, SAFI unicast
		CapRouteRefresh, 0,
		CapFourOctetAS, 4, 0, 0, byte(as >> 8), byte(as),
	}
	params := append([]byte{optParamCapabilities, byte(len(caps))}, caps...)
	body := make([]byte, 10, 10+len(params))
	body[0] = Version
	binary.BigEndian.PutUint16(body[1:3], as)
	binary.BigEndian.PutUint16(body[3:5], holdTime)
	copy(body[5:9], bgpID[:])
	body[9] = byte(len(params))
	return build(TypeOpen, append(body, params...))
}

// BuildKeepalive builds a KEEPALIVE (header only).
func BuildKeepalive() []byte {
	return build(TypeKeepalive, nil)
}

// BuildNotification builds a NOTIFICATION with the given error and data.
func BuildNotification(code, subcode uint8, data []byte) []byte {
	return build(TypeNotification, append([]byte{code, subcode}, data...))
}
