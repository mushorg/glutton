package smb

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func buildType3(domain, user, workstation string) []byte {
	msg := make([]byte, 64)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuthenticate)
	binary.LittleEndian.PutUint32(msg[60:64], ntlmNegotiateUnicode)

	payload := []byte{}
	put := func(descOff int, s string) {
		enc := encodeNoNUL(s)
		off := 64 + len(payload)
		binary.LittleEndian.PutUint16(msg[descOff:], uint16(len(enc)))
		binary.LittleEndian.PutUint16(msg[descOff+2:], uint16(len(enc)))
		binary.LittleEndian.PutUint32(msg[descOff+4:], uint32(off))
		payload = append(payload, enc...)
	}
	// Fake NT response buffer first, to prove it is never read.
	ntResp := bytes.Repeat([]byte{0xAA}, 24)
	binary.LittleEndian.PutUint16(msg[20:], uint16(len(ntResp)))
	binary.LittleEndian.PutUint16(msg[22:], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(msg[24:], uint32(64))
	payload = append(payload, ntResp...)
	put(28, domain)
	put(36, user)
	put(44, workstation)
	return append(msg, payload...)
}

func encodeNoNUL(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestParseAuthenticate(t *testing.T) {
	id := ParseAuthenticate(buildType3("CORP", "admin", "WS01"))
	require.Equal(t, "CORP", id.Domain)
	require.Equal(t, "admin", id.User)
	require.Equal(t, "WS01", id.Workstation)
}

func TestParseAuthenticateIgnoresNonType3(t *testing.T) {
	require.Equal(t, NTLMIdentity{}, ParseAuthenticate(buildChallengeFixture()))
	require.Equal(t, NTLMIdentity{}, ParseAuthenticate([]byte("not ntlm")))
}

func buildChallengeFixture() []byte {
	return BuildChallenge([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, "SERVER")
}

func TestBuildChallenge(t *testing.T) {
	msg := buildChallengeFixture()
	require.True(t, bytes.HasPrefix(msg, ntlmSignature))
	require.Equal(t, uint32(ntlmChallengeMsg), NTLMMessageType(msg))
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, msg[24:32])
	flags := binary.LittleEndian.Uint32(msg[20:24])
	require.NotZero(t, flags&ntlmNegotiateUnicode)
	require.NotZero(t, flags&ntlmNegotiateNTLM)
}

func TestFindNTLMSSPInWrappedBlob(t *testing.T) {
	ntlm := BuildChallenge([8]byte{}, "X")
	blob := append([]byte{0x60, 0x40, 0x06, 0x06, 0x2b}, ntlm...)
	got, ok := FindNTLMSSP(blob)
	require.True(t, ok)
	require.Equal(t, ntlm, got)

	_, ok = FindNTLMSSP([]byte("no signature here"))
	require.False(t, ok)
}

func TestSPNEGOTokensContainNTLMOID(t *testing.T) {
	init := SPNEGONegTokenInit()
	require.Equal(t, byte(0x60), init[0])
	require.True(t, bytes.Contains(init, oidNTLM))
	require.True(t, bytes.Contains(init, oidSPNEGO))

	chal := SPNEGOChallenge(BuildChallenge([8]byte{}, "X"))
	require.Equal(t, byte(0xa1), chal[0])
	require.True(t, bytes.Contains(chal, ntlmSignature))

	accept := SPNEGOAccept()
	require.Equal(t, byte(0xa1), accept[0])
	require.Contains(t, string(accept), "\x0a\x01\x00")
}

func TestBERLen(t *testing.T) {
	require.Equal(t, []byte{0x7f}, berLen(0x7f))
	require.Equal(t, []byte{0x81, 0x80}, berLen(0x80))
	require.Equal(t, []byte{0x82, 0x01, 0x00}, berLen(256))
}
