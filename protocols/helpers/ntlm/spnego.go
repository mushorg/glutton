package ntlm

import "bytes"

// NegTokenInit builds the server's initial SPNEGO blob (SMB Negotiate)
// advertising NTLMSSP as the supported mechanism.
func NegTokenInit() []byte {
	mechList := TLV(0x30, TLV(0x06, OIDNTLMSSP))
	mechTypes := TLV(0xa0, mechList)
	negInit := TLV(0x30, mechTypes)
	negToken := TLV(0xa0, negInit)
	spnego := append(TLV(0x06, OIDSPNEGO), negToken...)
	return TLV(0x60, spnego)
}

// NegTokenChallenge wraps an NTLMSSP Type 2 message in an SPNEGO NegTokenResp
// with negResult accept-incomplete and supportedMech NTLMSSP.
func NegTokenChallenge(ntlmType2 []byte) []byte {
	var b []byte
	b = append(b, TLV(0xa0, TLV(0x0a, []byte{0x01}))...) // accept-incomplete
	b = append(b, TLV(0xa1, TLV(0x06, OIDNTLMSSP))...)
	b = append(b, TLV(0xa2, TLV(0x04, ntlmType2))...)
	return TLV(0xa1, TLV(0x30, b))
}

// NegTokenAccept builds the final SPNEGO NegTokenResp with negResult
// accept-completed (SMB Session Setup success).
func NegTokenAccept() []byte {
	negResult := TLV(0xa0, []byte{0x0a, 0x01, 0x00})
	return TLV(0xa1, TLV(0x30, negResult))
}

// UnwrapSPNEGO returns the NTLM message inside a SPNEGO token and whether the
// token was SPNEGO. Accepted forms: GSS InitialContextToken (0x60) carrying a
// NegTokenInit, a bare NegTokenInit (0xa0) and a NegTokenResp (0xa1). Anything
// else (raw NTLM, malformed DER) is returned unchanged with false.
func UnwrapSPNEGO(tok []byte) ([]byte, bool) {
	if len(tok) < 2 {
		return tok, false
	}
	var neg []byte // the [0] NegTokenInit or [1] NegTokenResp
	switch tok[0] {
	case 0x60:
		inner := Value(tok, 0x60)
		t, oid, rest := Next(inner)
		if t != 0x06 || !bytes.Equal(oid, OIDSPNEGO) {
			return tok, false
		}
		neg = rest
	case 0xa0, 0xa1:
		neg = tok
	default:
		return tok, false
	}
	if len(neg) == 0 || (neg[0] != 0xa0 && neg[0] != 0xa1) {
		return tok, false
	}
	seq := Value(Value(neg, neg[0]), 0x30)
	for len(seq) > 0 {
		var tag byte
		var val []byte
		tag, val, seq = Next(seq)
		// mechToken (NegTokenInit) and responseToken (NegTokenResp) are both [2].
		if tag == 0xa2 {
			return Value(val, 0x04), true
		}
	}
	return nil, true
}
