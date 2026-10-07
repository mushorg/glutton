// Package dnp3 parses and builds DNP3 (IEEE 1815) data link layer frames.
//
// A link frame is a 10-byte header (start bytes 0x05 0x64, LENGTH, CONTROL,
// DEST and SRC as little-endian uint16, CRC) followed by user data in blocks
// of up to 16 bytes, each followed by its own CRC. LENGTH counts the control,
// address and user-data octets (no CRCs), so a header-only frame has LENGTH 5.
package dnp3

import (
	"encoding/binary"
	"errors"
)

const (
	// HeaderSize is the size of the link header including its CRC.
	HeaderSize = 10
	// MinLength is the LENGTH value of a frame without user data.
	MinLength = 5

	blockSize = 16
)

// Link-layer function codes. The meaning depends on the PRM bit.
const (
	// Primary (PRM=1, from the master).
	FuncResetLinkStates     = 0
	FuncTestLinkStates      = 2
	FuncConfirmedUserData   = 3
	FuncUnconfirmedUserData = 4
	FuncRequestLinkStatus   = 9

	// Secondary (PRM=0, replies).
	FuncACK          = 0
	FuncNACK         = 1
	FuncLinkStatus   = 11
	FuncNotSupported = 15
)

var (
	ErrShort     = errors.New("dnp3: short frame")
	ErrStart     = errors.New("dnp3: bad start bytes")
	ErrLength    = errors.New("dnp3: invalid length")
	ErrHeaderCRC = errors.New("dnp3: header crc mismatch")
	ErrDataCRC   = errors.New("dnp3: data block crc mismatch")
)

// CRC computes the CRC-16/DNP of data (polynomial 0x3D65, reflected, final
// complement). On the wire it is sent low byte first.
func CRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// Header is a decoded link-layer header.
type Header struct {
	Length  byte
	Control byte
	Dest    uint16
	Src     uint16
}

// ParseHeader decodes and verifies the first HeaderSize bytes of b.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShort
	}
	if b[0] != 0x05 || b[1] != 0x64 {
		return Header{}, ErrStart
	}
	if binary.LittleEndian.Uint16(b[8:10]) != CRC(b[:8]) {
		return Header{}, ErrHeaderCRC
	}
	h := Header{
		Length:  b[2],
		Control: b[3],
		Dest:    binary.LittleEndian.Uint16(b[4:6]),
		Src:     binary.LittleEndian.Uint16(b[6:8]),
	}
	if h.Length < MinLength {
		return Header{}, ErrLength
	}
	return h, nil
}

// DIR is true for frames sent by a master.
func (h Header) DIR() bool { return h.Control&0x80 != 0 }

// PRM is true for primary (request) frames.
func (h Header) PRM() bool { return h.Control&0x40 != 0 }

// Function is the 4-bit link function code.
func (h Header) Function() byte { return h.Control & 0x0f }

// Command names the link function, e.g. REQUEST_LINK_STATUS.
func (h Header) Command() string {
	f := h.Function()
	if h.PRM() {
		switch f {
		case FuncResetLinkStates:
			return "RESET_LINK_STATES"
		case FuncTestLinkStates:
			return "TEST_LINK_STATES"
		case FuncConfirmedUserData:
			return "CONFIRMED_USER_DATA"
		case FuncUnconfirmedUserData:
			return "UNCONFIRMED_USER_DATA"
		case FuncRequestLinkStatus:
			return "REQUEST_LINK_STATUS"
		}
		return "UNKNOWN"
	}
	return SecondaryName(f)
}

// SecondaryName names a secondary (reply) function code.
func SecondaryName(f byte) string {
	switch f {
	case FuncACK:
		return "ACK"
	case FuncNACK:
		return "NACK"
	case FuncLinkStatus:
		return "LINK_STATUS"
	case FuncNotSupported:
		return "NOT_SUPPORTED"
	}
	return "UNKNOWN"
}

// BodySize is the number of bytes that follow the header: the user data plus
// one CRC per started 16-byte block.
func (h Header) BodySize() int {
	n := int(h.Length) - MinLength
	return n + 2*((n+blockSize-1)/blockSize)
}

// UserData verifies every block CRC in body (as read after the header) and
// returns the user data with the CRCs removed.
func (h Header) UserData(body []byte) ([]byte, error) {
	if len(body) < h.BodySize() {
		return nil, ErrShort
	}
	var out []byte
	for rest := body[:h.BodySize()]; len(rest) > 0; {
		n := len(rest) - 2
		if n > blockSize {
			n = blockSize
		}
		if binary.LittleEndian.Uint16(rest[n:n+2]) != CRC(rest[:n]) {
			return nil, ErrDataCRC
		}
		out = append(out, rest[:n]...)
		rest = rest[n+2:]
	}
	return out, nil
}

// Secondary builds a header-only reply as sent by an outstation (DIR=0,
// PRM=0) from src to dest.
func Secondary(function byte, dest, src uint16) []byte {
	b := make([]byte, HeaderSize)
	b[0], b[1], b[2], b[3] = 0x05, 0x64, MinLength, function&0x0f
	binary.LittleEndian.PutUint16(b[4:6], dest)
	binary.LittleEndian.PutUint16(b[6:8], src)
	binary.LittleEndian.PutUint16(b[8:10], CRC(b[:8]))
	return b
}

// Reply returns the reply an outstation with link address own sends for a
// verified request header, or nil when it stays silent: the frame is not a
// primary frame from a master, is addressed to another station (including
// broadcast), or needs no confirmation.
func Reply(h Header, own uint16) []byte {
	if !h.DIR() || !h.PRM() || h.Dest != own {
		return nil
	}
	switch h.Function() {
	case FuncRequestLinkStatus:
		return Secondary(FuncLinkStatus, h.Src, own)
	case FuncResetLinkStates, FuncTestLinkStates, FuncConfirmedUserData:
		return Secondary(FuncACK, h.Src, own)
	case FuncUnconfirmedUserData:
		return nil
	}
	return Secondary(FuncNotSupported, h.Src, own)
}
