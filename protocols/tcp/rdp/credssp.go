package rdp

import (
	"crypto/rand"
	"encoding/binary"
	"unicode/utf16"
)

// NTLM message types (exported for use by the RDP handler).
const (
	NTLMMsgNegotiate    = 1
	NTLMMsgChallenge    = 2
	NTLMMsgAuthenticate = 3
)

const (
	ntlmSig = "NTLMSSP\x00"
	// challengeFlags: NEGOTIATE_UNICODE|REQUEST_TARGET|NEGOTIATE_NTLM|NEGOTIATE_ALWAYS_SIGN|
	// TARGET_TYPE_SERVER|NEGOTIATE_EXTENDED_SESSIONSECURITY|NEGOTIATE_TARGET_INFO|
	// NEGOTIATE_128|NEGOTIATE_KEY_EXCH|NEGOTIATE_56 (no VERSION → no Version field, payload at offset 48)
	challengeFlags uint32 = 0xe08a8205
)

// ParsedCredSSP holds data extracted from a CredSSP TSRequest.
type ParsedCredSSP struct {
	NTLMType    int    `json:"ntlm_type,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Username    string `json:"username,omitempty"`
	Workstation string `json:"workstation,omitempty"`
}

// ParseCredSSP extracts structured data from a CredSSP TSRequest.
// When the TSRequest carries an NTLM Type 3 Authenticate it populates
// Domain, Username, and Workstation from the UTF-16LE payload fields.
func ParseCredSSP(data []byte) ParsedCredSSP {
	ntlm := negoTokenFromTSRequest(data)
	if len(ntlm) < 12 || string(ntlm[:8]) != ntlmSig {
		return ParsedCredSSP{}
	}
	out := ParsedCredSSP{NTLMType: int(binary.LittleEndian.Uint32(ntlm[8:12]))}
	if out.NTLMType == NTLMMsgAuthenticate {
		out.Domain = readNTLMUTF16Field(ntlm, 28)
		out.Username = readNTLMUTF16Field(ntlm, 36)
		out.Workstation = readNTLMUTF16Field(ntlm, 44)
	}
	return out
}

// BuildTSRequestChallenge builds a CredSSP TSRequest carrying a random NTLM Type 2 Challenge.
func BuildTSRequestChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return WrapTSRequest(buildNTLMChallenge(challenge)), nil
}

// WrapTSRequest wraps an NTLM message in a CredSSP TSRequest (version 6).
// Structure: SEQUENCE { [0] INTEGER 6, [1] SEQUENCE OF { SEQUENCE { [0] OCTET STRING ntlm } } }
func WrapTSRequest(ntlm []byte) []byte {
	octet := derTLV(0x04, ntlm)
	ctx0 := derTLV(0xa0, octet)
	item := derTLV(0x30, ctx0)
	seqOf := derTLV(0x30, item)
	negoTokens := derTLV(0xa1, seqOf)
	version := []byte{0xa0, 0x03, 0x02, 0x01, 0x06}
	return derTLV(0x30, append(version, negoTokens...))
}

// negoTokenFromTSRequest extracts the raw NTLM bytes nested inside a CredSSP TSRequest.
// Walks: SEQUENCE → [1] → SEQUENCE OF → NegoDataItem SEQUENCE → [0] → OCTET STRING.
func negoTokenFromTSRequest(data []byte) []byte {
	inner := derValue(data, 0x30)
	for len(inner) > 0 {
		var tag byte
		var val []byte
		tag, val, inner = derNext(inner)
		if tag == 0xa1 {
			return derValue(derValue(derValue(derValue(val, 0x30), 0x30), 0xa0), 0x04)
		}
	}
	return nil
}

// buildNTLMChallenge builds an NTLM Type 2 Challenge with the given 8-byte server challenge.
// Payload (TargetName + TargetInfo AvPairs) starts at offset 48 (no Version field).
func buildNTLMChallenge(serverChallenge []byte) []byte {
	targetName := utf16LE("SERVER")
	avPairs := buildAvPairs("WORKGROUP", "SERVER")
	targetNameOff := 48
	targetInfoOff := targetNameOff + len(targetName)
	msg := make([]byte, targetInfoOff+len(avPairs))
	copy(msg[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgChallenge)
	// TargetNameFields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOff))
	// NegotiateFlags
	binary.LittleEndian.PutUint32(msg[20:24], challengeFlags)
	// ServerChallenge
	copy(msg[24:32], serverChallenge)
	// msg[32:40] = Reserved, already zero
	// TargetInfoFields
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOff))
	// Payload
	copy(msg[targetNameOff:], targetName)
	copy(msg[targetInfoOff:], avPairs)
	return msg
}

// buildAvPairs builds NTLM TargetInfo AvPairs: domain name, computer name, then EOL.
func buildAvPairs(domain, computer string) []byte {
	var b []byte
	b = appendAvPair(b, 2, utf16LE(domain))   // MsvAvNbDomainName
	b = appendAvPair(b, 1, utf16LE(computer)) // MsvAvNbComputerName
	b = appendAvPair(b, 0, nil)               // MsvAvEOL
	return b
}

func appendAvPair(b []byte, id uint16, val []byte) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], id)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	return append(append(b, hdr[:]...), val...)
}

// readNTLMUTF16Field reads a UTF-16LE string from the NTLM field descriptor at fieldOff.
// Each descriptor is: len(2 LE) + maxLen(2 LE) + offset(4 LE).
// DomainName is at 28, UserName at 36, Workstation at 44 — all fixed offsets per MS-NLMP.
func readNTLMUTF16Field(data []byte, fieldOff int) string {
	if fieldOff+8 > len(data) {
		return ""
	}
	l := int(binary.LittleEndian.Uint16(data[fieldOff:]))
	o := int(binary.LittleEndian.Uint32(data[fieldOff+4:]))
	if l == 0 || l%2 != 0 || o+l > len(data) {
		return ""
	}
	u16 := make([]uint16, l/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[o+2*i:])
	}
	return string(utf16.Decode(u16))
}

func utf16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return b
}

// DER helpers.

// derValue checks that data begins with the expected tag and returns its value bytes.
func derValue(data []byte, tag byte) []byte {
	if len(data) < 2 || data[0] != tag {
		return nil
	}
	v, _, ok := derLength(data[1:])
	if !ok {
		return nil
	}
	return v
}

// derNext splits off the first TLV from data, returning tag, value, and the remaining bytes.
func derNext(data []byte) (tag byte, value []byte, rest []byte) {
	if len(data) < 2 {
		return 0, nil, nil
	}
	tag = data[0]
	val, hdr, ok := derLength(data[1:])
	if !ok {
		return 0, nil, nil
	}
	return tag, val, data[1+hdr+len(val):]
}

// derLength parses a DER definite-form length starting at data[0].
// Returns the value bytes, the bytes consumed by the length field, and ok.
func derLength(data []byte) (value []byte, hdrBytes int, ok bool) {
	if len(data) == 0 {
		return nil, 0, false
	}
	b := data[0]
	if b < 0x80 {
		l := int(b)
		if 1+l > len(data) {
			return nil, 0, false
		}
		return data[1 : 1+l], 1, true
	}
	n := int(b & 0x7f)
	if n == 0 || 1+n > len(data) {
		return nil, 0, false
	}
	var l int
	for i := 0; i < n; i++ {
		l = l<<8 | int(data[1+i])
	}
	hdr := 1 + n
	if hdr+l > len(data) {
		return nil, 0, false
	}
	return data[hdr : hdr+l], hdr, true
}

// derTLV builds a DER TLV with the given tag and value bytes.
func derTLV(tag byte, value []byte) []byte {
	lenb := berLength(len(value)) // berLength is defined in mcs.go
	out := make([]byte, 1+len(lenb)+len(value))
	out[0] = tag
	copy(out[1:], lenb)
	copy(out[1+len(lenb):], value)
	return out
}
