// Package cql parses and builds Cassandra native protocol (CQL binary
// protocol) frames as spoken on tcp/9042.
//
// Wire format (native_protocol_v4.spec, v3-v5 share the header layout):
//
//	header v3+: byte version | byte flags | int16 stream | byte opcode | int32 length
//	header v1/v2: byte version | byte flags | int8 stream | byte opcode | int32 length
//	[string]: uint16 length | bytes
//	[long string]: int32 length | bytes
//	[bytes]: int32 length (negative = null) | bytes
//	[string map]: uint16 n | n * ([string] key, [string] value)
//	[string multimap]: uint16 n | n * ([string] key, [string list] values)
//
// The top bit of version is set on responses.
package cql

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Opcodes.
const (
	OpError         uint8 = 0x00
	OpStartup       uint8 = 0x01
	OpReady         uint8 = 0x02
	OpAuthenticate  uint8 = 0x03
	OpCredentials   uint8 = 0x04
	OpOptions       uint8 = 0x05
	OpSupported     uint8 = 0x06
	OpQuery         uint8 = 0x07
	OpResult        uint8 = 0x08
	OpPrepare       uint8 = 0x09
	OpExecute       uint8 = 0x0a
	OpRegister      uint8 = 0x0b
	OpEvent         uint8 = 0x0c
	OpBatch         uint8 = 0x0d
	OpAuthChallenge uint8 = 0x0e
	OpAuthResponse  uint8 = 0x0f
	OpAuthSuccess   uint8 = 0x10
)

// Error codes used in ERROR bodies.
const (
	ErrServer          uint32 = 0x0000
	ErrProtocol        uint32 = 0x000a
	ErrBadCredentials  uint32 = 0x0100
	ErrIsBootstrapping uint32 = 0x1002
)

// Header flags.
const (
	FlagCompression   uint8 = 0x01
	FlagTracing       uint8 = 0x02
	FlagCustomPayload uint8 = 0x04
	FlagWarning       uint8 = 0x08
	FlagUseBeta       uint8 = 0x10
)

const (
	// HeaderLen is the header size for protocol v3 and later.
	HeaderLen = 9
	// LegacyHeaderLen is the header size for protocol v1 and v2.
	LegacyHeaderLen = 8
	// MaxBodyLen caps a frame body; larger declared lengths are rejected.
	MaxBodyLen = 64 * 1024

	responseBit = 0x80
)

var opcodeNames = map[uint8]string{
	OpError:         "ERROR",
	OpStartup:       "STARTUP",
	OpReady:         "READY",
	OpAuthenticate:  "AUTHENTICATE",
	OpCredentials:   "CREDENTIALS",
	OpOptions:       "OPTIONS",
	OpSupported:     "SUPPORTED",
	OpQuery:         "QUERY",
	OpResult:        "RESULT",
	OpPrepare:       "PREPARE",
	OpExecute:       "EXECUTE",
	OpRegister:      "REGISTER",
	OpEvent:         "EVENT",
	OpBatch:         "BATCH",
	OpAuthChallenge: "AUTH_CHALLENGE",
	OpAuthResponse:  "AUTH_RESPONSE",
	OpAuthSuccess:   "AUTH_SUCCESS",
}

// OpcodeName returns the spec name of an opcode, or "opcode-<n>".
func OpcodeName(op uint8) string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	return fmt.Sprintf("opcode-%d", op)
}

// Header is a decoded frame header.
type Header struct {
	Version  uint8  `json:"version"`
	Response bool   `json:"response,omitempty"`
	Flags    uint8  `json:"flags,omitempty"`
	Stream   int16  `json:"stream"`
	Opcode   uint8  `json:"opcode"`
	Length   uint32 `json:"length"`
}

// HeaderSize returns the header length for a protocol version.
func HeaderSize(version uint8) int {
	if version < 3 {
		return LegacyHeaderLen
	}
	return HeaderLen
}

// ErrUnknownVersion is returned by ReadFrame when the first byte is not a
// protocol version 1-5 (non-CQL traffic). Only that byte has been consumed.
var ErrUnknownVersion = errors.New("cql: unknown protocol version")

// ErrBodyTooLarge is returned by ReadFrame when the declared body length
// exceeds MaxBodyLen. The header has been consumed, the body has not.
var ErrBodyTooLarge = errors.New("cql: frame body too large")

// ReadFrame reads one frame. It returns every byte consumed (even on error)
// and the header once it has been read in full.
func ReadFrame(r io.Reader) ([]byte, *Header, error) {
	first := make([]byte, 1)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, nil, err
	}
	version := first[0] &^ responseBit
	if version < 1 || version > 5 {
		return first, nil, ErrUnknownVersion
	}
	size := HeaderSize(version)
	raw := make([]byte, size)
	raw[0] = first[0]
	if n, err := io.ReadFull(r, raw[1:]); err != nil {
		return raw[:1+n], nil, err
	}
	hdr := &Header{Version: version, Response: first[0]&responseBit != 0, Flags: raw[1]}
	if size == LegacyHeaderLen {
		hdr.Stream = int16(int8(raw[2]))
		hdr.Opcode = raw[3]
		hdr.Length = binary.BigEndian.Uint32(raw[4:8])
	} else {
		hdr.Stream = int16(binary.BigEndian.Uint16(raw[2:4]))
		hdr.Opcode = raw[4]
		hdr.Length = binary.BigEndian.Uint32(raw[5:9])
	}
	if hdr.Length > MaxBodyLen {
		return raw, hdr, ErrBodyTooLarge
	}
	if hdr.Length == 0 {
		return raw, hdr, nil
	}
	frame := make([]byte, size+int(hdr.Length))
	copy(frame, raw)
	n, err := io.ReadFull(r, frame[size:])
	if err != nil {
		return frame[:size+n], hdr, err
	}
	return frame, hdr, nil
}

// BuildFrame builds a response frame with the given request version and
// stream; the body is sent uncompressed.
func BuildFrame(version uint8, stream int16, opcode uint8, body []byte) []byte {
	size := HeaderSize(version)
	out := make([]byte, size, size+len(body))
	out[0] = version | responseBit
	if size == LegacyHeaderLen {
		out[2] = byte(int8(stream))
		out[3] = opcode
		binary.BigEndian.PutUint32(out[4:8], uint32(len(body)))
	} else {
		binary.BigEndian.PutUint16(out[2:4], uint16(stream))
		out[4] = opcode
		binary.BigEndian.PutUint32(out[5:9], uint32(len(body)))
	}
	return append(out, body...)
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// MultimapEntry is one key of a [string multimap]; a slice keeps the wire
// order deterministic.
type MultimapEntry struct {
	Key    string
	Values []string
}

// StringMultimap encodes a [string multimap].
func StringMultimap(entries []MultimapEntry) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
	for _, e := range entries {
		b = appendString(b, e.Key)
		b = binary.BigEndian.AppendUint16(b, uint16(len(e.Values)))
		for _, v := range e.Values {
			b = appendString(b, v)
		}
	}
	return b
}

// StringBody encodes a body consisting of a single [string] (AUTHENTICATE).
func StringBody(s string) []byte {
	return appendString(nil, s)
}

// NullBytes encodes a null [bytes] value (AUTH_SUCCESS without a token).
func NullBytes() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff}
}

// ErrorBody encodes an ERROR body: [int] code | [string] message. Only codes
// without additional fields may be passed.
func ErrorBody(code uint32, msg string) []byte {
	b := binary.BigEndian.AppendUint32(nil, code)
	return appendString(b, msg)
}

// ErrShortBody is returned when a body ends inside a value.
var ErrShortBody = errors.New("cql: short body")

type reader struct {
	b []byte
}

func (r *reader) uint16() (uint16, error) {
	if len(r.b) < 2 {
		return 0, ErrShortBody
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v, nil
}

func (r *reader) int32() (int32, error) {
	if len(r.b) < 4 {
		return 0, ErrShortBody
	}
	v := int32(binary.BigEndian.Uint32(r.b))
	r.b = r.b[4:]
	return v, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || len(r.b) < n {
		return nil, ErrShortBody
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *reader) string() (string, error) {
	n, err := r.uint16()
	if err != nil {
		return "", err
	}
	v, err := r.take(int(n))
	return string(v), err
}

// ParseStringMap decodes a [string map] (STARTUP options).
func ParseStringMap(body []byte) (map[string]string, error) {
	r := &reader{b: body}
	n, err := r.uint16()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, min(int(n), 64))
	for i := 0; i < int(n); i++ {
		k, err := r.string()
		if err != nil {
			return m, err
		}
		v, err := r.string()
		if err != nil {
			return m, err
		}
		m[k] = v
	}
	return m, nil
}

// ParseStringList decodes a [string list] (REGISTER event types).
func ParseStringList(body []byte) ([]string, error) {
	r := &reader{b: body}
	n, err := r.uint16()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, min(int(n), 64))
	for i := 0; i < int(n); i++ {
		s, err := r.string()
		if err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

// ParseLongString decodes the leading [long string] of a QUERY or PREPARE
// body.
func ParseLongString(body []byte) (string, error) {
	r := &reader{b: body}
	n, err := r.int32()
	if err != nil {
		return "", err
	}
	v, err := r.take(int(n))
	return string(v), err
}

// ParseBytes decodes the leading [bytes] of an AUTH_RESPONSE body. A null
// value returns nil without error.
func ParseBytes(body []byte) ([]byte, error) {
	r := &reader{b: body}
	n, err := r.int32()
	if err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, nil
	}
	return r.take(int(n))
}

// ParsePlainSASL splits a SASL PLAIN token (authzid NUL authcid NUL passwd)
// as sent by PasswordAuthenticator clients.
func ParsePlainSASL(token []byte) (username, password string, ok bool) {
	var parts [][]byte
	start := 0
	for i, c := range token {
		if c == 0 {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return "", "", false
	}
	return string(parts[1]), string(parts[2]), true
}
