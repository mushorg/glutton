package rdp

import (
	"crypto/rand"
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// NTLM message types (exported for use by the RDP handler).
const (
	NTLMMsgNegotiate    = 1
	NTLMMsgChallenge    = 2
	NTLMMsgAuthenticate = 3
)

// NTLM Negotiate flag bits (MS-NLMP 2.2.2.5).
const (
	// ntlmFlagVersion is NTLMSSP_NEGOTIATE_VERSION (bit 25, 0x02000000).
	// When the client sets it the server must include a VERSION structure in
	// the Type 2 Challenge, shifting the payload from offset 48 to 56.
	ntlmFlagVersion uint32 = 0x02000000
)

const (
	ntlmSig = "NTLMSSP\x00"

	// challengeFlags: NEGOTIATE_UNICODE|REQUEST_TARGET|NEGOTIATE_NTLM|
	// NEGOTIATE_ALWAYS_SIGN|TARGET_TYPE_SERVER|NEGOTIATE_EXTENDED_SESSIONSECURITY|
	// NEGOTIATE_TARGET_INFO|NEGOTIATE_128|NEGOTIATE_KEY_EXCH|NEGOTIATE_56.
	// NEGOTIATE_VERSION (0x02000000) is ORed in when the client requests it.
	challengeFlagsBase uint32 = 0xe08a8205
)

// NTLM AvPair IDs (MS-NLMP 2.2.2.1).
const (
	avEOL             = 0 // MsvAvEOL
	avNbComputerName  = 1 // MsvAvNbComputerName
	avNbDomainName    = 2 // MsvAvNbDomainName
	avDnsComputerName = 3 // MsvAvDnsComputerName
	avDnsDomainName   = 4 // MsvAvDnsDomainName
	avTimestamp       = 7 // MsvAvTimestamp (FILETIME)
)

// filetimeEpochDiff is the number of 100-nanosecond intervals between
// 1601-01-01 (Windows FILETIME epoch) and 1970-01-01 (Unix epoch).
const filetimeEpochDiff = int64(116444736000000000)

// ParsedCredSSP holds data extracted from a CredSSP TSRequest.
type ParsedCredSSP struct {
	NTLMType       int    `json:"ntlm_type,omitempty"`
	NegotiateFlags uint32 `json:"negotiate_flags,omitempty"` // set on Type 1 (Negotiate)
	Domain         string `json:"domain,omitempty"`
	Username       string `json:"username,omitempty"`
	Workstation    string `json:"workstation,omitempty"`
}

// ParseCredSSP extracts structured data from a CredSSP TSRequest.
// For a Type 1 (Negotiate) it populates NegotiateFlags.
// For a Type 3 (Authenticate) it populates Domain, Username, and Workstation
// from the UTF-16LE payload fields.
func ParseCredSSP(data []byte) ParsedCredSSP {
	ntlm := negoTokenFromTSRequest(data)
	if len(ntlm) < 12 || string(ntlm[:8]) != ntlmSig {
		return ParsedCredSSP{}
	}
	out := ParsedCredSSP{NTLMType: int(binary.LittleEndian.Uint32(ntlm[8:12]))}
	switch out.NTLMType {
	case NTLMMsgNegotiate:
		if len(ntlm) >= 16 {
			out.NegotiateFlags = binary.LittleEndian.Uint32(ntlm[12:16])
		}
	case NTLMMsgAuthenticate:
		out.Domain = readNTLMUTF16Field(ntlm, 28)
		out.Username = readNTLMUTF16Field(ntlm, 36)
		out.Workstation = readNTLMUTF16Field(ntlm, 44)
	}
	return out
}

// NTLMChallengeOptions configures an NTLM Type 2 Challenge message.
type NTLMChallengeOptions struct {
	// Computer is the NetBIOS computer name (e.g. "WIN-ABC123").
	Computer string
	// Domain is the NetBIOS domain/workgroup name (e.g. "WORKGROUP").
	Domain string
	// ClientFlags are the NegotiateFlags from the client's Type 1 message.
	// When ntlmFlagVersion is set the Challenge includes a VERSION block and
	// the payload shifts from offset 48 to 56.
	ClientFlags uint32
	// Now is used for the MsvAvTimestamp AvPair. Zero → time.Now().
	Now time.Time
}

// BuildTSRequestChallenge builds a CredSSP TSRequest carrying a random NTLM
// Type 2 Challenge. The sensor identity is taken from Identity().
func BuildTSRequestChallenge() ([]byte, error) {
	computer, domain := Identity()
	return BuildTSRequestChallengeWith(NTLMChallengeOptions{Computer: computer, Domain: domain})
}

// BuildTSRequestChallengeWith builds a CredSSP TSRequest with the given
// options. It is used by the RDP handler so the Challenge identity matches the
// TLS certificate and so that VERSION is included when the client asks for it.
func BuildTSRequestChallengeWith(opts NTLMChallengeOptions) ([]byte, error) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	return WrapTSRequest(buildNTLMChallenge(challenge, opts)), nil
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

// buildNTLMChallenge builds an NTLM Type 2 Challenge.
//
// Payload layout when NEGOTIATE_VERSION is not set (offset 48):
//
//	TargetName (UTF-16LE domain) | TargetInfo AvPairs
//
// Payload layout when NEGOTIATE_VERSION is set (offset 56):
//
//	VERSION (8 bytes) | TargetName | TargetInfo AvPairs
//
// We advertise Windows Server 2019 / Windows 10 1809 (build 17763) when asked.
func buildNTLMChallenge(serverChallenge []byte, opts NTLMChallengeOptions) []byte {
	targetName := utf16LE(opts.Domain)
	avPairs := buildAvPairs(opts.Domain, opts.Computer, opts.Now)

	includeVersion := opts.ClientFlags&ntlmFlagVersion != 0
	flags := challengeFlagsBase
	var payloadOff int
	if includeVersion {
		flags |= ntlmFlagVersion
		payloadOff = 56 // 48 fixed + 8 VERSION
	} else {
		payloadOff = 48 // no VERSION
	}

	targetNameOff := payloadOff
	targetInfoOff := targetNameOff + len(targetName)
	msg := make([]byte, targetInfoOff+len(avPairs))

	copy(msg[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgChallenge)
	// TargetNameFields (len, maxLen, offset)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOff))
	// NegotiateFlags
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	// ServerChallenge
	copy(msg[24:32], serverChallenge)
	// msg[32:40] = Reserved (already zero)
	// TargetInfoFields (len, maxLen, offset)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOff))
	if includeVersion {
		// VERSION (MS-NLMP 2.2.2.10): Windows 10.0 build 17763, NTLM rev 15.
		//   ProductMajorVersion: 0x0a
		//   ProductMinorVersion: 0x00
		//   ProductBuild:        0x4563 (LE) = 17763
		//   Reserved[3]:         0x00 0x00 0x00
		//   NTLMRevisionCurrent: 0x0f
		copy(msg[48:56], []byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f})
	}
	copy(msg[targetNameOff:], targetName)
	copy(msg[targetInfoOff:], avPairs)
	return msg
}

// buildAvPairs builds the NTLM TargetInfo AvPairs block.
// Windows sends (in order): NbDomainName, NbComputerName, DnsDomainName,
// DnsComputerName, Timestamp, EOL.
func buildAvPairs(domain, computer string, now time.Time) []byte {
	var b []byte
	b = appendAvPair(b, avNbDomainName, utf16LE(domain))
	b = appendAvPair(b, avNbComputerName, utf16LE(computer))
	// For a workgroup machine DNS names match their NetBIOS counterparts.
	b = appendAvPair(b, avDnsDomainName, utf16LE(domain))
	b = appendAvPair(b, avDnsComputerName, utf16LE(computer))
	// MsvAvTimestamp: Windows FILETIME (100-ns intervals since 1601-01-01).
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, toFILETIME(now))
	b = appendAvPair(b, avTimestamp, ts)
	b = appendAvPair(b, avEOL, nil)
	return b
}

// toFILETIME converts a time.Time to a Windows FILETIME (100-ns intervals
// since 1601-01-01 00:00:00 UTC).
func toFILETIME(t time.Time) uint64 {
	return uint64(t.UnixNano()/100 + filetimeEpochDiff)
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
	for i := range n {
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
