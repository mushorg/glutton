// Package acpp parses Apple AirPort Admin protocol (ACP, magic "acpp",
// tcp/5009) message headers and builds the error replies a base station sends.
//
// The header layout follows the public reverse-engineering in airpyrt-tools
// (acp/message.py, struct "!4s8i12x32s48x") and Metasploit's
// Rex::Proto::ACPP::Message: 128 bytes, big-endian, Adler-32 checksums.
package acpp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/adler32"
)

// HeaderSize is the fixed ACP header length.
const HeaderSize = 128

// Version is the header version AirPort Utility and base stations send.
// airpyrt also accepts 0x00000001.
const Version = 0x00030001

// MaxBody caps the body read after a header. getprop/setprop bodies are a few
// property elements; firmware uploads are the only large ones.
const MaxBody = 64 * 1024

// Magic starts every ACP message.
var Magic = []byte("acpp")

// Error codes from Apple's shared CoreUtils error space (kChecksumErr, ...),
// which ACP replies use (AirPort Utility reports e.g. ACPDevice -6753).
// 0 is success.
const (
	ErrChecksum       int32 = -6713
	ErrVersion        int32 = -6715
	ErrUnsupported    int32 = -6735
	ErrAuthentication int32 = -6754
)

// ErrNotACPP is returned when the data does not start with the ACP magic.
var ErrNotACPP = errors.New("not an ACP header")

var commandNames = map[uint32]string{
	0x01: "echo",
	0x03: "flash_primary",
	0x04: "flash_4",
	0x05: "flash_secondary",
	0x06: "flash_bootloader",
	0x14: "getprop",
	0x15: "setprop",
	0x16: "perform",
	0x17: "monitor_17",
	0x18: "monitor",
	0x19: "rpc",
	0x1a: "auth",
	0x1b: "feat",
}

// CommandName names an ACP command, or returns "unknown".
func CommandName(cmd uint32) string {
	if name, ok := commandNames[cmd]; ok {
		return name
	}
	return "unknown"
}

// Header is a parsed ACP message header.
type Header struct {
	Version        uint32
	HeaderChecksum uint32
	BodyChecksum   uint32
	BodySize       int32 // -1 for a stream header (no body follows)
	Flags          uint32
	Unused         uint32
	Command        uint32
	ErrorCode      int32
	Key            [32]byte // password XORed with the static ACP keystream
}

// ParseHeader parses the first HeaderSize bytes of raw.
func ParseHeader(raw []byte) (Header, error) {
	if len(raw) < HeaderSize || !bytes.Equal(raw[:4], Magic) {
		return Header{}, ErrNotACPP
	}
	be := binary.BigEndian
	h := Header{
		Version:        be.Uint32(raw[4:]),
		HeaderChecksum: be.Uint32(raw[8:]),
		BodyChecksum:   be.Uint32(raw[12:]),
		BodySize:       int32(be.Uint32(raw[16:])),
		Flags:          be.Uint32(raw[20:]),
		Unused:         be.Uint32(raw[24:]),
		Command:        be.Uint32(raw[28:]),
		ErrorCode:      int32(be.Uint32(raw[32:])),
	}
	copy(h.Key[:], raw[48:80])
	return h, nil
}

// Checksum is the Adler-32 of the header with its checksum field zeroed.
func Checksum(raw []byte) uint32 {
	var tmp [HeaderSize]byte
	copy(tmp[:], raw[:HeaderSize])
	binary.BigEndian.PutUint32(tmp[8:], 0)
	return adler32.Checksum(tmp[:])
}

// Validate returns the error code a base station answers raw's header with:
// ErrVersion, ErrChecksum, ErrUnsupported for an unknown command, or 0.
func Validate(h Header, raw []byte) int32 {
	switch {
	case h.Version != Version && h.Version != 0x00000001:
		return ErrVersion
	case Checksum(raw) != h.HeaderChecksum:
		return ErrChecksum
	case CommandName(h.Command) == "unknown":
		return ErrUnsupported
	}
	return 0
}

// BuildReply builds a body-less reply header for cmd carrying errCode.
func BuildReply(cmd uint32, errCode int32) []byte {
	raw := make([]byte, HeaderSize)
	be := binary.BigEndian
	copy(raw, Magic)
	be.PutUint32(raw[4:], Version)
	be.PutUint32(raw[12:], adler32.Checksum(nil)) // empty body: adler32("") = 1
	be.PutUint32(raw[28:], cmd)
	be.PutUint32(raw[32:], uint32(errCode))
	be.PutUint32(raw[8:], Checksum(raw))
	return raw
}
