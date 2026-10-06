// Package rfb parses client messages and builds server messages for the
// RFB (VNC) protocol, versions 3.3, 3.7 and 3.8 (RFC 6143).
package rfb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

// Version is the negotiated protocol version.
type Version int

const (
	Version33 Version = iota
	Version37
	Version38
)

func (v Version) String() string {
	switch v {
	case Version37:
		return "3.7"
	case Version38:
		return "3.8"
	}
	return "3.3"
}

// VersionLen is the length of a ProtocolVersion message ("RFB 003.008\n").
const VersionLen = 12

// ServerVersion is the ProtocolVersion the honeypot announces.
var ServerVersion = []byte("RFB 003.008\n")

// ParseVersion parses a client ProtocolVersion. Unknown minor versions map to
// 3.3 and anything newer than 3.8 maps to 3.8, as RFC 6143 §7.1.1 requires.
func ParseVersion(data []byte) (Version, bool) {
	if len(data) != VersionLen || !bytes.HasPrefix(data, []byte("RFB ")) || data[7] != '.' || data[11] != '\n' {
		return Version33, false
	}
	major, err := strconv.Atoi(string(data[4:7]))
	if err != nil {
		return Version33, false
	}
	minor, err := strconv.Atoi(string(data[8:11]))
	if err != nil {
		return Version33, false
	}
	switch {
	case major > 3 || (major == 3 && minor >= 8):
		return Version38, true
	case major == 3 && minor == 7:
		return Version37, true
	}
	return Version33, true
}

// Security types.
const (
	SecurityInvalid uint8 = 0
	SecurityNone    uint8 = 1
	SecurityVNCAuth uint8 = 2
)

// SecurityTypeName names a security type for decoded events.
func SecurityTypeName(t uint8) string {
	switch t {
	case SecurityInvalid:
		return "Invalid"
	case SecurityNone:
		return "None"
	case SecurityVNCAuth:
		return "VNCAuthentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 30:
		return "AppleARD"
	}
	return fmt.Sprintf("0x%02x", t)
}

// SecurityTypes builds the 3.7+ security handshake: a count byte followed by
// the offered types.
func SecurityTypes(types ...uint8) []byte {
	return append([]byte{uint8(len(types))}, types...)
}

// SecurityType33 builds the 3.3 handshake, where the server picks the type.
func SecurityType33(t uint8) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(t))
}

// ChallengeLen is the size of the VNC authentication challenge and response.
const ChallengeLen = 16

// SecurityResult builds a SecurityResult. The failure reason is only sent
// to 3.8 clients; earlier versions do not expect one.
func SecurityResult(ok bool, v Version, reason string) []byte {
	if ok {
		return []byte{0, 0, 0, 0}
	}
	out := []byte{0, 0, 0, 1}
	if v == Version38 {
		out = binary.BigEndian.AppendUint32(out, uint32(len(reason)))
		out = append(out, reason...)
	}
	return out
}

// PixelFormat is the 16-byte PIXEL_FORMAT structure.
type PixelFormat struct {
	BPP, Depth                      uint8
	BigEndian, TrueColour           bool
	RedMax, GreenMax, BlueMax       uint16
	RedShift, GreenShift, BlueShift uint8
}

// DefaultPixelFormat is 32bpp little-endian true colour, which is what most
// VNC servers advertise.
var DefaultPixelFormat = PixelFormat{
	BPP: 32, Depth: 24, TrueColour: true,
	RedMax: 255, GreenMax: 255, BlueMax: 255,
	RedShift: 16, GreenShift: 8, BlueShift: 0,
}

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// Bytes encodes the pixel format, including its 3 padding bytes.
func (p PixelFormat) Bytes() []byte {
	out := []byte{p.BPP, p.Depth, boolByte(p.BigEndian), boolByte(p.TrueColour)}
	out = binary.BigEndian.AppendUint16(out, p.RedMax)
	out = binary.BigEndian.AppendUint16(out, p.GreenMax)
	out = binary.BigEndian.AppendUint16(out, p.BlueMax)
	return append(out, p.RedShift, p.GreenShift, p.BlueShift, 0, 0, 0)
}

// ServerInit builds the ServerInit message.
func ServerInit(width, height uint16, pf PixelFormat, name string) []byte {
	out := binary.BigEndian.AppendUint16(nil, width)
	out = binary.BigEndian.AppendUint16(out, height)
	out = append(out, pf.Bytes()...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(name)))
	return append(out, name...)
}

// Client-to-server message types.
const (
	MsgSetPixelFormat           uint8 = 0
	MsgSetEncodings             uint8 = 2
	MsgFramebufferUpdateRequest uint8 = 3
	MsgKeyEvent                 uint8 = 4
	MsgPointerEvent             uint8 = 5
	MsgClientCutText            uint8 = 6
)

// clientHeaderLen is the fixed size of each client message after its type
// byte; variable-length bodies follow it.
var clientHeaderLen = map[uint8]int{
	MsgSetPixelFormat:           19,
	MsgSetEncodings:             3,
	MsgFramebufferUpdateRequest: 9,
	MsgKeyEvent:                 7,
	MsgPointerEvent:             5,
	MsgClientCutText:            7,
}

var clientMessageNames = map[uint8]string{
	MsgSetPixelFormat:           "SetPixelFormat",
	MsgSetEncodings:             "SetEncodings",
	MsgFramebufferUpdateRequest: "FramebufferUpdateRequest",
	MsgKeyEvent:                 "KeyEvent",
	MsgPointerEvent:             "PointerEvent",
	MsgClientCutText:            "ClientCutText",
}

// ClientMessageName names a client message type, or returns "" if unknown.
func ClientMessageName(t uint8) string {
	return clientMessageNames[t]
}

// ClientHeaderLen returns the fixed header size following the type byte.
func ClientHeaderLen(t uint8) (int, bool) {
	n, ok := clientHeaderLen[t]
	return n, ok
}

// ClientBodyLen returns the variable body size announced in a message header
// (the bytes after the type byte). Fixed-size messages have no body.
func ClientBodyLen(t uint8, header []byte) uint64 {
	switch t {
	case MsgSetEncodings:
		if len(header) >= 3 {
			return uint64(binary.BigEndian.Uint16(header[1:3])) * 4
		}
	case MsgClientCutText:
		if len(header) >= 7 {
			return uint64(binary.BigEndian.Uint32(header[3:7]))
		}
	}
	return 0
}

// Encodings decodes the encoding list of a SetEncodings body.
func Encodings(body []byte) []int32 {
	out := make([]int32, 0, len(body)/4)
	for i := 0; i+4 <= len(body); i += 4 {
		out = append(out, int32(binary.BigEndian.Uint32(body[i:i+4])))
	}
	return out
}

// KeyEvent decodes a KeyEvent header into its down flag and keysym.
func KeyEvent(header []byte) (bool, uint32) {
	if len(header) < 7 {
		return false, 0
	}
	return header[0] != 0, binary.BigEndian.Uint32(header[3:7])
}

// KeysymName renders a keysym as its Latin-1 character when printable, or as
// hex otherwise (e.g. 0xff0d for Return).
func KeysymName(sym uint32) string {
	if (sym >= 0x20 && sym <= 0x7e) || (sym >= 0xa0 && sym <= 0xff) {
		return string(rune(sym))
	}
	return fmt.Sprintf("0x%04x", sym)
}
