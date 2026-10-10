package smb

import (
	"bytes"
	"encoding/binary"
)

// NTLMSSP handling for SMB Session Setup. Glutton answers a Type 1 (NEGOTIATE)
// with a Type 2 (CHALLENGE) and accepts the Type 3 (AUTHENTICATE), recording
// the account, domain, and workstation. The LM/NT response buffers (the
// credential material) are deliberately never read or stored.

var ntlmSignature = []byte("NTLMSSP\x00")

const (
	ntlmNegotiate    = 1
	ntlmChallengeMsg = 2
	ntlmAuthenticate = 3

	ntlmNegotiateUnicode     = 0x00000001
	ntlmRequestTarget        = 0x00000004
	ntlmNegotiateNTLM        = 0x00000200
	ntlmNegotiateAlwaysSign  = 0x00008000
	ntlmTargetTypeServer     = 0x00020000
	ntlmNegotiateTargetInfo  = 0x00800000
	ntlmNegotiateExtSecurity = 0x00080000

	// MsvAvNbDomainName / MsvAvEOL AV_PAIR ids.
	ntlmAvNbDomain = 0x0002
	ntlmAvEOL      = 0x0000
)

// NTLM OID 1.3.6.1.4.1.311.2.2.10 and SPNEGO OID 1.3.6.1.5.5.2 (DER-encoded).
var (
	oidNTLM   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	oidSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
)

// FindNTLMSSP returns the NTLMSSP message embedded in a (possibly SPNEGO-wrapped)
// security blob, located by its signature so both raw and GSS-wrapped blobs work.
func FindNTLMSSP(blob []byte) ([]byte, bool) {
	i := bytes.Index(blob, ntlmSignature)
	if i < 0 {
		return nil, false
	}
	return blob[i:], true
}

// NTLMMessageType returns the NTLMSSP MessageType, or 0 when the buffer is short.
func NTLMMessageType(ntlm []byte) uint32 {
	if len(ntlm) < 12 || !bytes.HasPrefix(ntlm, ntlmSignature) {
		return 0
	}
	return binary.LittleEndian.Uint32(ntlm[8:12])
}

// NTLMIdentity holds the non-secret identity fields of a Type 3 message.
type NTLMIdentity struct {
	Domain      string
	User        string
	Workstation string
}

// ParseAuthenticate reads the domain, user, and workstation from a Type 3
// AUTHENTICATE message. The LM/NT challenge responses are not read.
func ParseAuthenticate(ntlm []byte) NTLMIdentity {
	if NTLMMessageType(ntlm) != ntlmAuthenticate || len(ntlm) < 64 {
		return NTLMIdentity{}
	}
	flags := binary.LittleEndian.Uint32(ntlm[60:64])
	unicode := flags&ntlmNegotiateUnicode != 0
	// Field descriptors: Len(2), MaxLen(2), Offset(4). Order after the type:
	// Lm(12), Nt(20), Domain(28), User(36), Workstation(44).
	return NTLMIdentity{
		Domain:      ntlmField(ntlm, 28, unicode),
		User:        ntlmField(ntlm, 36, unicode),
		Workstation: ntlmField(ntlm, 44, unicode),
	}
}

func ntlmField(ntlm []byte, descOff int, unicode bool) string {
	if descOff+8 > len(ntlm) {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(ntlm[descOff : descOff+2]))
	offset := int(binary.LittleEndian.Uint32(ntlm[descOff+4 : descOff+8]))
	if length == 0 || offset+length > len(ntlm) {
		return ""
	}
	raw := ntlm[offset : offset+length]
	if unicode {
		s, _ := decodeUnicodeStringN(raw, length/2)
		return s
	}
	return string(raw)
}

// BuildChallenge builds an NTLMSSP Type 2 CHALLENGE for the given server
// challenge, advertising targetName as both the server name and NetBIOS domain.
func BuildChallenge(serverChallenge [8]byte, targetName string) []byte {
	target := encodeString(targetName, true)
	// Target info: NbDomainName AV pair + EOL.
	var info bytes.Buffer
	binary.Write(&info, binary.LittleEndian, uint16(ntlmAvNbDomain))
	binary.Write(&info, binary.LittleEndian, uint16(len(target)))
	info.Write(target)
	binary.Write(&info, binary.LittleEndian, uint16(ntlmAvEOL))
	binary.Write(&info, binary.LittleEndian, uint16(0))

	flags := uint32(ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateNTLM |
		ntlmNegotiateAlwaysSign | ntlmTargetTypeServer | ntlmNegotiateTargetInfo |
		ntlmNegotiateExtSecurity)

	const headerLen = 48
	targetOff := headerLen
	infoOff := targetOff + len(target)

	out := make([]byte, headerLen)
	copy(out[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(out[8:12], ntlmChallengeMsg)
	// TargetName fields.
	binary.LittleEndian.PutUint16(out[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(targetOff))
	binary.LittleEndian.PutUint32(out[20:24], flags)
	copy(out[24:32], serverChallenge[:])
	// Reserved[32:40] stays zero.
	// TargetInfo fields.
	binary.LittleEndian.PutUint16(out[40:42], uint16(info.Len()))
	binary.LittleEndian.PutUint16(out[42:44], uint16(info.Len()))
	binary.LittleEndian.PutUint32(out[44:48], uint32(infoOff))

	out = append(out, target...)
	out = append(out, info.Bytes()...)
	return out
}

// SPNEGONegTokenInit builds the server's initial SPNEGO blob (sent in the
// Negotiate response) advertising NTLMSSP as the supported mechanism.
func SPNEGONegTokenInit() []byte {
	mechList := berTLV(0x30, berTLV(0x06, oidNTLM))
	mechTypes := berTLV(0xa0, mechList)
	negInit := berTLV(0x30, mechTypes)
	negToken := berTLV(0xa0, negInit)
	spnego := append(berTLV(0x06, oidSPNEGO), negToken...)
	return berTLV(0x60, spnego)
}

// SPNEGOChallenge wraps an NTLMSSP Type 2 message in an SPNEGO NegTokenResp
// with negResult accept-incomplete.
func SPNEGOChallenge(ntlmType2 []byte) []byte {
	negResult := berTLV(0xa0, []byte{0x0a, 0x01, 0x01})
	supported := berTLV(0xa1, berTLV(0x06, oidNTLM))
	respToken := berTLV(0xa2, berTLV(0x04, ntlmType2))
	seq := berTLV(0x30, concat(negResult, supported, respToken))
	return berTLV(0xa1, seq)
}

// SPNEGOAccept builds the final SPNEGO NegTokenResp with negResult
// accept-completed.
func SPNEGOAccept() []byte {
	negResult := berTLV(0xa0, []byte{0x0a, 0x01, 0x00})
	return berTLV(0xa1, berTLV(0x30, negResult))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
