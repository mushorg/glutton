// Package pcom parses and builds Unitronics PCOM over TCP (tcp/20256). The
// framing and both checksums are checked against one captured session; the
// ID reply layout and the error reply are NOT captured and are a guess from
// third-party descriptions, not the vendor spec.
//
// PCOM/TCP header (6 bytes), then the PCOM message:
//
//	u16 LE   transaction id (echoed in replies)
//	u8       mode: 0x65 ASCII, 0x66 binary
//	u8       reserved (0)
//	u16 LE   length of the message that follows
//
// ASCII message: '/' unit(2 chars) command(2 chars) data checksum(2 hex) '\r'.
// The checksum is the sum of the bytes between '/' and the checksum, mod 256.
//
// Binary message: "/_OPLC" followed by an 18-byte header remainder, data, a
// 2-byte footer checksum and '\'. Bytes 22-23 of the message are the
// little-endian header checksum (two's complement of the sum of bytes 0-21),
// bytes 20-21 the data length, and the footer checksum is the same function
// over the data. Byte 6 is the unit id and byte 12 is treated as the command.
package pcom

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderLen is the PCOM/TCP header.
	HeaderLen = 6
	// MaxBody bounds the message length that is read.
	MaxBody = 4096

	ModeASCII  = 0x65
	ModeBinary = 0x66

	// BinaryHeaderLen is the binary message up to and including the header checksum.
	BinaryHeaderLen = 24
	// BinaryTrailerLen is the footer checksum plus ETX.
	BinaryTrailerLen = 3

	// ErrCodeUnrecognized is the error reply code for commands the
	// honeypot does not answer.
	ErrCodeUnrecognized = "01"
)

// BinarySignature starts every binary message.
var BinarySignature = []byte("/_OPLC")

var (
	ErrBadMode  = errors.New("pcom: bad mode")
	ErrBadLen   = errors.New("pcom: bad length")
	ErrTooLarge = errors.New("pcom: frame too large")
)

// Header is the PCOM/TCP header.
type Header struct {
	TID    uint16
	Mode   byte
	Length uint16
}

// ReadFrame reads one PCOM/TCP frame and returns the header, the message and
// the raw wire bytes. raw holds whatever was read when err is not nil.
func ReadFrame(r io.Reader) (Header, []byte, []byte, error) {
	raw := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, raw)
	if err != nil {
		return Header{}, nil, raw[:n], err
	}
	h := Header{TID: binary.LittleEndian.Uint16(raw[0:2]), Mode: raw[2], Length: binary.LittleEndian.Uint16(raw[4:6])}
	if h.Mode != ModeASCII && h.Mode != ModeBinary || raw[3] != 0 {
		return h, nil, raw, ErrBadMode
	}
	if h.Length == 0 {
		return h, nil, raw, ErrBadLen
	}
	if h.Length > MaxBody {
		return h, nil, raw, ErrTooLarge
	}
	raw = append(raw, make([]byte, h.Length)...)
	m, err := io.ReadFull(r, raw[HeaderLen:])
	if err != nil {
		return h, nil, raw[:HeaderLen+m], err
	}
	return h, raw[HeaderLen:], raw, nil
}

// Build returns a PCOM/TCP frame carrying msg; Length is set from msg.
func Build(h Header, msg []byte) []byte {
	out := make([]byte, HeaderLen, HeaderLen+len(msg))
	binary.LittleEndian.PutUint16(out[0:2], h.TID)
	out[2] = h.Mode
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(msg)))
	return append(out, msg...)
}

// ASCIIRequest is a parsed ASCII message.
type ASCIIRequest struct {
	Unit       string // two ASCII characters, the unit id
	Command    string // two characters, e.g. ID
	Data       string // between the command and the checksum
	ChecksumOK bool
}

// ASCIIChecksum returns the two-hex-digit checksum of s.
func ASCIIChecksum(s string) string {
	var sum byte
	for i := 0; i < len(s); i++ {
		sum += s[i]
	}
	return fmt.Sprintf("%02X", sum)
}

// ParseASCII parses '/' unit command data checksum '\r'. The checksum field
// is not required to be valid: scanners send malformed ones and the capture
// holds one that is, so ChecksumOK reports it instead.
func ParseASCII(msg []byte) (ASCIIRequest, bool) {
	// '/' + unit(2) + command(2) + '\r' is the shortest message with a command
	if len(msg) < 6 || msg[0] != '/' || msg[len(msg)-1] != '\r' {
		return ASCIIRequest{}, false
	}
	body := string(msg[1 : len(msg)-1])
	req := ASCIIRequest{Unit: body[0:2], Command: body[2:4]}
	if len(body) >= 6 {
		req.Data = body[4 : len(body)-2]
		req.ChecksumOK = ASCIIChecksum(body[:len(body)-2]) == body[len(body)-2:]
	} else {
		req.Data = body[4:]
	}
	return req, true
}

// BuildASCII returns '/' kind payload checksum '\r'.
func BuildASCII(kind byte, payload string) []byte {
	body := string(kind) + payload
	return []byte("/" + body + ASCIIChecksum(body) + "\r")
}

// Identity is the persona in ID replies.
type Identity struct {
	ModelCode string // six characters
	Hardware  byte   // one character
	OSMajor   int
	OSMinor   int
	OSBuild   int
}

// RandomIdentity returns a Vision-series identity whose build number varies
// so sensors do not share a fingerprint.
func RandomIdentity() Identity {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return Identity{ModelCode: "070500", Hardware: 'B', OSMajor: 3, OSMinor: 1, OSBuild: 10 + int(b[0])%40}
}

// IDReply answers an ID command. The field layout (model(6) hardware(1)
// os major(2) minor(2) build(2)) is a guess.
func IDReply(unit string, id Identity) []byte {
	return BuildASCII('A', fmt.Sprintf("%sID%s%c%02d%02d%02d", unit, id.ModelCode, id.Hardware, id.OSMajor, id.OSMinor, id.OSBuild))
}

// ErrorReply answers a command that is not supported. The /E layout is a guess.
func ErrorReply(unit, code string) []byte {
	return BuildASCII('E', unit+code)
}

// BinaryRequest is a parsed binary message.
type BinaryRequest struct {
	Unit     byte
	Command  byte
	Data     []byte
	HeaderOK bool // header checksum matches
}

// BinaryChecksum is the 16-bit two's complement of the sum of b.
func BinaryChecksum(b []byte) uint16 {
	var sum uint16
	for _, c := range b {
		sum += uint16(c)
	}
	return -sum
}

// LooksLikeBinary reports whether msg has the binary signature.
func LooksLikeBinary(msg []byte) bool {
	return len(msg) >= len(BinarySignature) && string(msg[:len(BinarySignature)]) == string(BinarySignature)
}

// ParseBinary parses a binary message.
func ParseBinary(msg []byte) (BinaryRequest, bool) {
	if !LooksLikeBinary(msg) || len(msg) < BinaryHeaderLen+BinaryTrailerLen {
		return BinaryRequest{}, false
	}
	dataLen := int(binary.LittleEndian.Uint16(msg[20:22]))
	if BinaryHeaderLen+dataLen+BinaryTrailerLen > len(msg) {
		return BinaryRequest{}, false
	}
	return BinaryRequest{
		Unit:     msg[6],
		Command:  msg[12],
		Data:     msg[BinaryHeaderLen : BinaryHeaderLen+dataLen],
		HeaderOK: binary.LittleEndian.Uint16(msg[22:24]) == BinaryChecksum(msg[:22]),
	}, true
}

// BinaryReply echoes the request header with no data and valid checksums.
// Real devices answer with command-specific data; none was captured.
func BinaryReply(req []byte) []byte {
	out := make([]byte, BinaryHeaderLen, BinaryHeaderLen+BinaryTrailerLen)
	copy(out, req[:BinaryHeaderLen])
	binary.LittleEndian.PutUint16(out[20:22], 0)
	binary.LittleEndian.PutUint16(out[22:24], BinaryChecksum(out[:22]))
	out = binary.LittleEndian.AppendUint16(out, 0)
	return append(out, '\\')
}
