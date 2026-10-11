package ntlm

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// filetimeEpochDiff is the number of 100-nanosecond intervals between
// 1601-01-01 (Windows FILETIME epoch) and 1970-01-01 (Unix epoch).
const FiletimeEpochDiff = int64(116444736000000000)

// EncodeUTF16LE encodes s as UTF-16LE without a NUL terminator.
func EncodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return b
}

// DecodeUTF16LE decodes a UTF-16LE byte slice (no NUL required).
func DecodeUTF16LE(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u16))
}

// ReadField copies the byte field described at fieldOff (len/maxlen/offset).
func ReadField(data []byte, fieldOff int) []byte {
	if fieldOff+8 > len(data) {
		return nil
	}
	l := int(binary.LittleEndian.Uint16(data[fieldOff:]))
	o := int(binary.LittleEndian.Uint32(data[fieldOff+4:]))
	if l == 0 || o < 0 || o+l > len(data) {
		return nil
	}
	return append([]byte(nil), data[o:o+l]...)
}

// ReadUTF16Field reads a UTF-16LE string from the NTLM field descriptor at fieldOff.
// DomainName is at 28, UserName at 36, Workstation at 44 (MS-NLMP).
func ReadUTF16Field(data []byte, fieldOff int) string {
	raw := ReadField(data, fieldOff)
	if len(raw) == 0 || len(raw)%2 != 0 {
		return ""
	}
	return DecodeUTF16LE(raw)
}

// ToFILETIME converts a time.Time to a Windows FILETIME (100-ns intervals
// since 1601-01-01 00:00:00 UTC).
func ToFILETIME(t time.Time) uint64 {
	return uint64(t.UnixNano()/100 + FiletimeEpochDiff)
}
