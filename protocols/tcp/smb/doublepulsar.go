package smb

import "encoding/binary"

// DoublePulsarXORKey derives the 4-byte XOR key DoublePulsar uses to obfuscate
// its TRANS2 SESSION_SETUP payloads from the signature seed s. The key schedule
// is the one used by the implant and by public detection tooling; seeds span the
// low 16 bits, so a caller that does not know the seed can recover the key by
// trying every value of s in [0, 0xffff].
func DoublePulsarXORKey(s uint32) uint32 {
	x := 2*uint64(s) ^ (((uint64(s)&0xff00 | (uint64(s) << 16)) << 8) | (((uint64(s) >> 16) | uint64(s)&0xff0000) >> 8))
	return uint32(x & 0xffffffff)
}

// XORInto writes src XORed with the 4-byte key (applied little-endian and
// repeating from the first byte) into dst, which must be at least len(src).
func XORInto(dst, src []byte, key uint32) {
	var k [4]byte
	binary.LittleEndian.PutUint32(k[:], key)
	for i := range src {
		dst[i] = src[i] ^ k[i%4]
	}
}

// XORApply returns src XORed with the repeating 4-byte key. DoublePulsar
// encrypts and decrypts its payload the same way, so this both obfuscates and
// recovers it.
func XORApply(src []byte, key uint32) []byte {
	out := make([]byte, len(src))
	XORInto(out, src, key)
	return out
}

// Trans2TotalDataCount returns TotalDataCount from an SMB_COM_TRANSACTION2
// request body positioned after the 32-byte SMB header.
func Trans2TotalDataCount(body []byte) uint32 {
	// WordCount(1) + TotalParameterCount(2) + TotalDataCount(2).
	if len(body) < 5 {
		return 0
	}
	return uint32(binary.LittleEndian.Uint16(body[3:5]))
}

// Trans2Data returns the data bytes carried in an initial SMB_COM_TRANSACTION2
// request. pdu starts at the SMB header (DataOffset is relative to it).
func Trans2Data(pdu []byte) []byte {
	const hdr = 32
	if len(pdu) < hdr+27 {
		return nil
	}
	body := pdu[hdr:]
	// DataCount USHORT at body[23:25], DataOffset USHORT at body[25:27].
	count := uint32(binary.LittleEndian.Uint16(body[23:25]))
	off := uint32(binary.LittleEndian.Uint16(body[25:27]))
	return sliceRange(pdu, off, count)
}

// DoublePulsar commands, carried in the TRANS2 SESSION_SETUP Timeout field.
// TODO: only exec (0xc8) is confirmed against a published capture; confirm ping
// and kill against a real capture before relying on them.
const (
	DPOpPing = 0x23
	DPOpExec = 0xc8
	DPOpKill = 0x77
)

// Trans2Timeout returns the Timeout field of an SMB_COM_TRANSACTION2 request
// body positioned after the 32-byte SMB header.
func Trans2Timeout(body []byte) uint32 {
	// WordCount(1) + 6 words + MaxSetupCount(1) + Reserved(1) + Flags(2) = 13.
	if len(body) < 17 {
		return 0
	}
	return binary.LittleEndian.Uint32(body[13:17])
}

// DoublePulsarOpcode derives the command from the Timeout field: the sum of its
// four bytes, truncated to a byte.
func DoublePulsarOpcode(timeout uint32) byte {
	return byte(timeout) + byte(timeout>>8) + byte(timeout>>16) + byte(timeout>>24)
}

// DoublePulsarXORKey64 derives the XOR key from the full 64-bit signature the
// implant returns in the SMB header's SecurityFeatures field.
func DoublePulsarXORKey64(s uint64) uint32 {
	x := 2*s ^ (((s&0xff00 | (s << 16)) << 8) | (((s >> 16) | s&0xff0000) >> 8))
	return uint32(x & 0xffffffff)
}

// DoublePulsarArchX64 reports whether the signature advertises an x64 implant.
func DoublePulsarArchX64(s uint64) bool { return s>>32 != 0 }

// Trans2Parameters returns the parameter bytes carried in an initial
// SMB_COM_TRANSACTION2 request. pdu starts at the SMB header.
func Trans2Parameters(pdu []byte) []byte {
	const hdr = 32
	if len(pdu) < hdr+23 {
		return nil
	}
	body := pdu[hdr:]
	count := uint32(binary.LittleEndian.Uint16(body[19:21]))
	off := uint32(binary.LittleEndian.Uint16(body[21:23]))
	return sliceRange(pdu, off, count)
}
