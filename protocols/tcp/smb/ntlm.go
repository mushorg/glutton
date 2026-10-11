package smb

import "github.com/mushorg/glutton/protocols/helpers/ntlm"

// NTLMSSP/SPNEGO for SMB Session Setup. Wire encoding lives in helpers/ntlm;
// this file keeps the smb package API stable for handlers and tests.

// NTLMIdentity holds the non-secret identity fields of a Type 3 message.
type NTLMIdentity = ntlm.Identity

// FindNTLMSSP returns the NTLMSSP message embedded in a (possibly SPNEGO-wrapped)
// security blob.
func FindNTLMSSP(blob []byte) ([]byte, bool) { return ntlm.Find(blob) }

// NTLMMessageType returns the NTLMSSP MessageType, or 0 when the buffer is short.
func NTLMMessageType(msg []byte) uint32 { return ntlm.MessageType(msg) }

// ParseAuthenticate reads the domain, user, and workstation from a Type 3
// AUTHENTICATE message. The LM/NT challenge responses are not read.
func ParseAuthenticate(msg []byte) NTLMIdentity { return ntlm.ParseIdentity(msg) }

// BuildChallenge builds an NTLMSSP Type 2 CHALLENGE for the given server
// challenge, advertising targetName as both the server name and NetBIOS domain.
func BuildChallenge(serverChallenge [8]byte, targetName string) []byte {
	return ntlm.BuildSMBChallenge(serverChallenge, targetName)
}

// SPNEGONegTokenInit builds the server's initial SPNEGO blob (sent in the
// Negotiate response) advertising NTLMSSP as the supported mechanism.
func SPNEGONegTokenInit() []byte { return ntlm.NegTokenInit() }

// SPNEGOChallenge wraps an NTLMSSP Type 2 message in an SPNEGO NegTokenResp
// with negResult accept-incomplete.
func SPNEGOChallenge(ntlmType2 []byte) []byte { return ntlm.NegTokenChallenge(ntlmType2) }

// SPNEGOAccept builds the final SPNEGO NegTokenResp with negResult
// accept-completed.
func SPNEGOAccept() []byte { return ntlm.NegTokenAccept() }

const (
	ntlmNegotiate    = ntlm.MsgNegotiate
	ntlmChallengeMsg = ntlm.MsgChallenge
	ntlmAuthenticate = ntlm.MsgAuthenticate

	ntlmNegotiateUnicode = ntlm.FlagUnicode
	ntlmNegotiateNTLM    = ntlm.FlagNTLM
)

var (
	ntlmSignature = []byte(ntlm.Signature)
	oidNTLM       = ntlm.OIDNTLMSSP
	oidSPNEGO     = ntlm.OIDSPNEGO
)
