package rdp

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
)

// NTLM message types (exported for use by the RDP handler).
const (
	NTLMMsgNegotiate    = ntlm.MsgNegotiate
	NTLMMsgChallenge    = ntlm.MsgChallenge
	NTLMMsgAuthenticate = ntlm.MsgAuthenticate
)

const (
	ntlmFlagVersion   = ntlm.FlagVersion
	ntlmSig           = ntlm.Signature
	filetimeEpochDiff = ntlm.FiletimeEpochDiff
	avEOL             = ntlm.AvEOL
	avNbComputerName  = ntlm.AvNbComputerName
	avNbDomainName    = ntlm.AvNbDomainName
	avDnsComputerName = ntlm.AvDnsComputerName
	avDnsDomainName   = ntlm.AvDnsDomainName
	avTimestamp       = ntlm.AvTimestamp
)

var (
	oidSPNEGO  = ntlm.OIDSPNEGO
	oidNTLMSSP = ntlm.OIDNTLMSSP
)

// ParsedCredSSP holds data extracted from a CredSSP TSRequest.
type ParsedCredSSP struct {
	NTLMType int `json:"ntlm_type,omitempty"`
	// SPNEGO is set when the NTLM message arrived inside a SPNEGO token
	// (GSS NegTokenInit or NegTokenResp), as Windows clients send it.
	SPNEGO         bool   `json:"spnego,omitempty"`
	NegotiateFlags uint32 `json:"negotiate_flags,omitempty"` // Type 1 and Type 3
	Domain         string `json:"domain,omitempty"`
	Username       string `json:"username,omitempty"`
	Workstation    string `json:"workstation,omitempty"`
	// NTLMVersion is "NTLMv1", "NTLMv2", or "anonymous", from the length of
	// the Type 3 NtChallengeResponse.
	NTLMVersion string `json:"ntlm_version,omitempty"`
	// NTResponseLen is the NtChallengeResponse length on Type 3.
	NTResponseLen int `json:"nt_response_len,omitempty"`
	// Fields below are inputs to NLA verification (MS-NLMP 2.2.2.6, MS-CSSP 2.2.1).
	// They are not copied onto decoded frames.
	NtChallengeResponse       []byte `json:"-"`
	EncryptedRandomSessionKey []byte `json:"-"`
	CredSSPVersion            int    `json:"-"`
	ClientNonce               []byte `json:"-"`
	PubKeyAuth                []byte `json:"-"`
	AuthInfo                  []byte `json:"-"`
}

// ParseCredSSP extracts structured data from a CredSSP TSRequest.
// For a Type 1 (Negotiate) it populates NegotiateFlags.
// For a Type 3 (Authenticate) it populates Domain, Username, Workstation,
// NtChallengeResponse, EncryptedRandomSessionKey, and NegotiateFlags.
// Version, clientNonce, pubKeyAuth, and authInfo come from the TSRequest wrapper.
func ParseCredSSP(data []byte) ParsedCredSSP {
	version, pubKeyAuth, authInfo, clientNonce := tsRequestFields(data)
	out := ParsedCredSSP{
		CredSSPVersion: version,
		PubKeyAuth:     pubKeyAuth,
		AuthInfo:       authInfo,
		ClientNonce:    clientNonce,
	}
	raw, wrapped := ntlm.UnwrapSPNEGO(negoTokenFromTSRequest(data))
	if ntlm.MessageType(raw) == 0 {
		return out
	}
	out.SPNEGO = wrapped
	out.NTLMType = int(ntlm.MessageType(raw))
	switch out.NTLMType {
	case NTLMMsgNegotiate:
		if len(raw) >= 16 {
			out.NegotiateFlags = binary.LittleEndian.Uint32(raw[12:16])
		}
	case NTLMMsgAuthenticate:
		auth := ntlm.ParseAuthenticate(raw)
		out.Domain = auth.Domain
		out.Username = auth.User
		out.Workstation = auth.Workstation
		out.NtChallengeResponse = auth.NtChallengeResponse
		out.NTResponseLen = auth.NTResponseLen
		out.NTLMVersion = auth.Version
		out.NegotiateFlags = auth.NegotiateFlags
		out.EncryptedRandomSessionKey = auth.EncryptedRandomSessionKey
	}
	return out
}

// NTLMChallengeOptions configures an NTLM Type 2 Challenge message for CredSSP.
type NTLMChallengeOptions struct {
	// Computer is the NetBIOS computer name (e.g. "WIN-ABC123").
	Computer string
	// Domain is the NetBIOS domain/workgroup name (e.g. "WORKGROUP").
	Domain string
	// ClientFlags are the NegotiateFlags from the client's Type 1 message.
	// When NEGOTIATE_VERSION is set the Challenge includes a VERSION block and
	// the payload shifts from offset 48 to 56.
	ClientFlags uint32
	// Now is used for the MsvAvTimestamp AvPair. Zero → time.Now().
	Now time.Time
	// SPNEGO wraps the Challenge in a NegTokenResp, which is what a client
	// expects when its Negotiate arrived inside SPNEGO.
	SPNEGO bool
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
	out, _, err := BuildTSRequestChallengeNonce(opts)
	return out, err
}

// BuildTSRequestChallengeNonce is BuildTSRequestChallengeWith that also
// returns the 8-byte server challenge, which is needed to crack the
// NTLMv2 response the client sends in its Authenticate.
func BuildTSRequestChallengeNonce(opts NTLMChallengeOptions) (tsRequest, serverChallenge []byte, err error) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	msg := buildNTLMChallenge(challenge, opts)
	if opts.SPNEGO {
		msg = ntlm.NegTokenChallenge(msg)
	}
	return WrapTSRequest(msg), challenge, nil
}

// StatusLogonFailure is NTSTATUS STATUS_LOGON_FAILURE.
const StatusLogonFailure uint32 = 0xC000006D

// BuildTSRequestError builds the CredSSP TSRequest a Windows server sends when
// authentication fails: SEQUENCE { [0] version 6, [4] errorCode NTSTATUS }.
func BuildTSRequestError(status uint32) []byte {
	// DER INTEGER is signed: prefix 0x00 when the high bit is set.
	code := []byte{byte(status >> 24), byte(status >> 16), byte(status >> 8), byte(status)}
	if code[0]&0x80 != 0 {
		code = append([]byte{0}, code...)
	}
	version := ntlm.TLV(0xa0, ntlm.TLV(0x02, []byte{0x06}))
	return ntlm.TLV(0x30, append(version, ntlm.TLV(0xa4, ntlm.TLV(0x02, code))...))
}

// WrapTSRequest wraps an NTLM message in a CredSSP TSRequest (version 6).
// Structure: SEQUENCE { [0] INTEGER 6, [1] SEQUENCE OF { SEQUENCE { [0] OCTET STRING ntlm } } }
func WrapTSRequest(msg []byte) []byte {
	return wrapTSRequest(6, msg, nil, nil, nil)
}

// BuildTSRequestPubKeyAuth builds a TSRequest carrying only the server's
// sealed pubKeyAuth confirmation (MS-CSSP 2.2.1).
func BuildTSRequestPubKeyAuth(version int, pubKeyAuth []byte) []byte {
	if version <= 0 {
		version = 6
	}
	return wrapTSRequest(version, nil, pubKeyAuth, nil, nil)
}

// wrapTSRequest builds a CredSSP TSRequest with the given optional fields.
func wrapTSRequest(version int, msg, pubKeyAuth, authInfo, clientNonce []byte) []byte {
	var b []byte
	b = append(b, ntlm.TLV(0xa0, derIntTLV(version))...)
	if len(msg) > 0 {
		octet := ntlm.TLV(0x04, msg)
		ctx0 := ntlm.TLV(0xa0, octet)
		item := ntlm.TLV(0x30, ctx0)
		seqOf := ntlm.TLV(0x30, item)
		b = append(b, ntlm.TLV(0xa1, seqOf)...)
	}
	if len(authInfo) > 0 {
		b = append(b, ntlm.TLV(0xa2, ntlm.TLV(0x04, authInfo))...)
	}
	if len(pubKeyAuth) > 0 {
		b = append(b, ntlm.TLV(0xa3, ntlm.TLV(0x04, pubKeyAuth))...)
	}
	if len(clientNonce) > 0 {
		b = append(b, ntlm.TLV(0xa5, ntlm.TLV(0x04, clientNonce))...)
	}
	return ntlm.TLV(0x30, b)
}

func derIntTLV(n int) []byte {
	if n < 0 {
		n = 0
	}
	if n < 0x80 {
		return ntlm.TLV(0x02, []byte{byte(n)})
	}
	var v []byte
	for n > 0 {
		v = append([]byte{byte(n)}, v...)
		n >>= 8
	}
	if v[0]&0x80 != 0 {
		v = append([]byte{0}, v...)
	}
	return ntlm.TLV(0x02, v)
}

// negoTokenFromTSRequest extracts the raw NTLM bytes nested inside a CredSSP TSRequest.
// Walks: SEQUENCE → [1] → SEQUENCE OF → NegoDataItem SEQUENCE → [0] → OCTET STRING.
func negoTokenFromTSRequest(data []byte) []byte {
	inner := ntlm.Value(data, 0x30)
	for len(inner) > 0 {
		var tag byte
		var val []byte
		tag, val, inner = ntlm.Next(inner)
		if tag == 0xa1 {
			return ntlm.Value(ntlm.Value(ntlm.Value(ntlm.Value(val, 0x30), 0x30), 0xa0), 0x04)
		}
	}
	return nil
}

// tsRequestFields reads version [0], authInfo [2], pubKeyAuth [3], and
// clientNonce [5] from a TSRequest (MS-CSSP 2.2.1).
func tsRequestFields(data []byte) (version int, pubKeyAuth, authInfo, clientNonce []byte) {
	inner := ntlm.Value(data, 0x30)
	for len(inner) > 0 {
		var tag byte
		var val []byte
		tag, val, inner = ntlm.Next(inner)
		switch tag {
		case 0xa0:
			version = derInteger(val)
		case 0xa2:
			authInfo = append([]byte(nil), ntlm.Value(val, 0x04)...)
		case 0xa3:
			pubKeyAuth = append([]byte(nil), ntlm.Value(val, 0x04)...)
		case 0xa5:
			clientNonce = append([]byte(nil), ntlm.Value(val, 0x04)...)
		}
	}
	return
}

func derInteger(val []byte) int {
	content := ntlm.Value(val, 0x02)
	if len(content) == 0 {
		return 0
	}
	n := 0
	for _, b := range content {
		n = n<<8 | int(b)
	}
	return n
}

func buildNTLMChallenge(serverChallenge []byte, opts NTLMChallengeOptions) []byte {
	return ntlm.BuildChallenge(ntlm.ChallengeOptions{
		ServerChallenge: serverChallenge,
		Domain:          opts.Domain,
		Computer:        opts.Computer,
		ClientFlags:     opts.ClientFlags,
		Now:             opts.Now,
		RichTargetInfo:  true,
	})
}

// Thin aliases so nla.go and tests keep a local vocabulary.
func utf16LE(s string) []byte                        { return ntlm.EncodeUTF16LE(s) }
func toFILETIME(t time.Time) uint64                  { return ntlm.ToFILETIME(t) }
func derTLV(tag byte, value []byte) []byte           { return ntlm.TLV(tag, value) }
func derValue(data []byte, tag byte) []byte          { return ntlm.Value(data, tag) }
func derNext(data []byte) (byte, []byte, []byte)     { return ntlm.Next(data) }
func readNTLMField(data []byte, fieldOff int) []byte { return ntlm.ReadField(data, fieldOff) }
func unwrapSPNEGO(tok []byte) ([]byte, bool)         { return ntlm.UnwrapSPNEGO(tok) }
func wrapNegTokenResp(msg []byte) []byte             { return ntlm.NegTokenChallenge(msg) }

// buildAvPairs returns the TargetInfo AvPairs from a rich Challenge (tests).
func buildAvPairs(domain, computer string, now time.Time) []byte {
	msg := ntlm.BuildChallenge(ntlm.ChallengeOptions{
		ServerChallenge: make([]byte, 8),
		Domain:          domain,
		Computer:        computer,
		Now:             now,
		RichTargetInfo:  true,
	})
	if len(msg) < 48 {
		return nil
	}
	infoOff := int(binary.LittleEndian.Uint32(msg[44:48]))
	infoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	if infoOff < 0 || infoOff+infoLen > len(msg) {
		return nil
	}
	return append([]byte(nil), msg[infoOff:infoOff+infoLen]...)
}
