// Package ntlm provides shared NTLMSSP and SPNEGO helpers for protocol handlers
// (SMB Session Setup, RDP CredSSP/NLA). Protocol envelopes (SMB security blobs,
// CredSSP TSRequest) stay in the handlers.
package ntlm

import (
	"bytes"
	"encoding/binary"
)

// Signature is the NTLMSSP message signature (MS-NLMP 2.2.1).
const Signature = "NTLMSSP\x00"

// NTLM message types (MS-NLMP 2.2.1).
const (
	MsgNegotiate    = 1
	MsgChallenge    = 2
	MsgAuthenticate = 3
)

// Negotiate flag bits (MS-NLMP 2.2.2.5).
const (
	FlagUnicode                 uint32 = 0x00000001
	FlagRequestTarget           uint32 = 0x00000004
	FlagNTLM                    uint32 = 0x00000200
	FlagExtendedSessionSecurity uint32 = 0x00080000
	FlagTargetTypeServer        uint32 = 0x00020000
	FlagAlwaysSign              uint32 = 0x00008000
	FlagTargetInfo              uint32 = 0x00800000
	FlagKeyExch                 uint32 = 0x40000000
	FlagVersion                 uint32 = 0x02000000 // NEGOTIATE_VERSION
)

// AvPair IDs (MS-NLMP 2.2.2.1).
const (
	AvEOL             = 0
	AvNbComputerName  = 1
	AvNbDomainName    = 2
	AvDnsComputerName = 3
	AvDnsDomainName   = 4
	AvTimestamp       = 7
)

// OID value bytes (without the DER OID tag/length).
var (
	// OIDNTLMSSP is 1.3.6.1.4.1.311.2.2.10.
	OIDNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// OIDSPNEGO is 1.3.6.1.5.5.2.
	OIDSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
)

var signature = []byte(Signature)

// Find returns the NTLMSSP message embedded in a (possibly SPNEGO-wrapped)
// security blob, located by its signature so both raw and GSS-wrapped blobs work.
func Find(blob []byte) ([]byte, bool) {
	i := bytes.Index(blob, signature)
	if i < 0 {
		return nil, false
	}
	return blob[i:], true
}

// MessageType returns the NTLMSSP MessageType, or 0 when the buffer is short.
func MessageType(msg []byte) uint32 {
	if len(msg) < 12 || !bytes.HasPrefix(msg, signature) {
		return 0
	}
	return binary.LittleEndian.Uint32(msg[8:12])
}

// Identity holds the non-secret identity fields of a Type 3 message.
type Identity struct {
	Domain      string
	User        string
	Workstation string
}

// Authenticate is a parsed Type 3 AUTHENTICATE message. Response buffers are
// copied for callers that verify (RDP NLA); SMB must not persist them.
type Authenticate struct {
	Identity
	NegotiateFlags            uint32
	NtChallengeResponse       []byte
	EncryptedRandomSessionKey []byte
	NTResponseLen             int
	// Version is "NTLMv1", "NTLMv2", or "anonymous", from NtChallengeResponse length.
	Version string
}

// ParseIdentity reads domain, user, and workstation from a Type 3 message.
// The LM/NT challenge responses are not read.
func ParseIdentity(msg []byte) Identity {
	if MessageType(msg) != MsgAuthenticate || len(msg) < 64 {
		return Identity{}
	}
	flags := binary.LittleEndian.Uint32(msg[60:64])
	unicode := flags&FlagUnicode != 0
	return Identity{
		Domain:      fieldString(msg, 28, unicode),
		User:        fieldString(msg, 36, unicode),
		Workstation: fieldString(msg, 44, unicode),
	}
}

// ParseAuthenticate reads identity and response fields from a Type 3 message.
func ParseAuthenticate(msg []byte) Authenticate {
	if MessageType(msg) != MsgAuthenticate {
		return Authenticate{}
	}
	out := Authenticate{
		Identity: Identity{
			Domain:      ReadUTF16Field(msg, 28),
			User:        ReadUTF16Field(msg, 36),
			Workstation: ReadUTF16Field(msg, 44),
		},
		NtChallengeResponse: ReadField(msg, 20),
	}
	if len(msg) >= 22 {
		out.NTResponseLen = int(binary.LittleEndian.Uint16(msg[20:22]))
		out.Version = VersionFromNTLen(out.NTResponseLen)
	}
	// Full AUTHENTICATE_MESSAGE is 64 bytes before payload
	// (EncryptedRandomSessionKeyFields at 52, NegotiateFlags at 60). The short
	// 56-byte form used by older tests keeps flags at 52.
	if authenticatePayloadOff(msg) >= 64 && len(msg) >= 64 {
		out.NegotiateFlags = binary.LittleEndian.Uint32(msg[60:64])
		out.EncryptedRandomSessionKey = ReadField(msg, 52)
	} else if len(msg) >= 56 {
		out.NegotiateFlags = binary.LittleEndian.Uint32(msg[52:56])
	}
	return out
}

// VersionFromNTLen classifies an NtChallengeResponse by length (MS-NLMP
// 2.2.2.6, 2.2.2.8): empty for anonymous, 24 bytes for NTLMv1, longer for NTLMv2.
func VersionFromNTLen(ntLen int) string {
	switch {
	case ntLen == 0:
		return "anonymous"
	case ntLen == 24:
		return "NTLMv1"
	case ntLen > 24:
		return "NTLMv2"
	}
	return ""
}

func authenticatePayloadOff(msg []byte) int {
	if len(msg) < 36 {
		return 0
	}
	return int(binary.LittleEndian.Uint32(msg[32:36]))
}

func fieldString(msg []byte, descOff int, unicode bool) string {
	raw := ReadField(msg, descOff)
	if len(raw) == 0 {
		return ""
	}
	if unicode {
		return DecodeUTF16LE(raw)
	}
	return string(raw)
}
