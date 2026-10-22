// Package rcon parses Valve Source RCON packets (srcds remote console,
// tcp/27015) and builds the replies a server sends to a failed login.
//
// The layout follows the Valve Developer Community "Source RCON Protocol"
// page: a little-endian int32 size (the bytes that follow it), int32 request
// id, int32 type, a NUL-terminated ASCII body and a trailing empty string.
package rcon

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderSize is the size, id and type prefix of every packet.
const HeaderSize = 12

// MinSize and MaxSize bound the declared size field: an empty body is
// id + type + two NULs, and the protocol caps packets at 4096 bytes.
const (
	MinSize = 10
	MaxSize = 4096
)

// MaxBody caps the body read after a header.
const MaxBody = MaxSize - MinSize

// Packet types. Type 2 is EXECCOMMAND from a client and AUTH_RESPONSE from
// the server.
const (
	TypeResponseValue int32 = 0
	TypeExecCommand   int32 = 2
	TypeAuthResponse  int32 = 2
	TypeAuth          int32 = 3
)

// AuthFailedID is the request id an AUTH_RESPONSE carries when the password
// was wrong.
const AuthFailedID int32 = -1

// ErrSize is returned when the size field is outside MinSize..MaxSize.
var ErrSize = errors.New("rcon packet size out of range")

// Header is the fixed prefix of a packet.
type Header struct {
	Size int32
	ID   int32
	Type int32
}

// ParseHeader parses the first HeaderSize bytes of raw.
func ParseHeader(raw []byte) (Header, error) {
	if len(raw) < HeaderSize {
		return Header{}, fmt.Errorf("rcon header too short: %d bytes", len(raw))
	}
	hdr := Header{
		Size: int32(binary.LittleEndian.Uint32(raw[0:])),
		ID:   int32(binary.LittleEndian.Uint32(raw[4:])),
		Type: int32(binary.LittleEndian.Uint32(raw[8:])),
	}
	if hdr.Size < MinSize || hdr.Size > MaxSize {
		return hdr, ErrSize
	}
	return hdr, nil
}

// CommandName names a client packet type, or returns "unknown".
func CommandName(typ int32) string {
	switch typ {
	case TypeAuth:
		return "auth"
	case TypeExecCommand:
		return "exec"
	case TypeResponseValue:
		return "response"
	}
	return "unknown"
}

// BuildPacket encodes one packet with a correct size field.
func BuildPacket(id, typ int32, body string) []byte {
	pkt := make([]byte, HeaderSize, HeaderSize+len(body)+2)
	binary.LittleEndian.PutUint32(pkt[0:], uint32(MinSize+len(body)))
	binary.LittleEndian.PutUint32(pkt[4:], uint32(id))
	binary.LittleEndian.PutUint32(pkt[8:], uint32(typ))
	pkt = append(pkt, body...)
	return append(pkt, 0, 0)
}

// BuildAuthFailure is what srcds sends for a wrong password: an empty
// RESPONSE_VALUE echoing the request id, then an AUTH_RESPONSE with id -1.
func BuildAuthFailure(id int32) []byte {
	reply := BuildPacket(id, TypeResponseValue, "")
	return append(reply, BuildPacket(AuthFailedID, TypeAuthResponse, "")...)
}
