package ntlm

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func buildType3(domain, user, workstation string) []byte {
	msg := make([]byte, 64)
	copy(msg[0:8], signature)
	binary.LittleEndian.PutUint32(msg[8:12], MsgAuthenticate)
	binary.LittleEndian.PutUint32(msg[60:64], FlagUnicode)

	payload := []byte{}
	put := func(descOff int, s string) {
		enc := EncodeUTF16LE(s)
		off := 64 + len(payload)
		binary.LittleEndian.PutUint16(msg[descOff:], uint16(len(enc)))
		binary.LittleEndian.PutUint16(msg[descOff+2:], uint16(len(enc)))
		binary.LittleEndian.PutUint32(msg[descOff+4:], uint32(off))
		payload = append(payload, enc...)
	}
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

func TestParseIdentity(t *testing.T) {
	id := ParseIdentity(buildType3("CORP", "admin", "WS01"))
	require.Equal(t, "CORP", id.Domain)
	require.Equal(t, "admin", id.User)
	require.Equal(t, "WS01", id.Workstation)
}

func TestParseIdentityIgnoresNonType3(t *testing.T) {
	require.Equal(t, Identity{}, ParseIdentity(BuildSMBChallenge([8]byte{1}, "SERVER")))
	require.Equal(t, Identity{}, ParseIdentity([]byte("not ntlm")))
}

func TestParseAuthenticate(t *testing.T) {
	msg := buildType3("ACME", "jsmith", "LAPTOP")
	got := ParseAuthenticate(msg)
	require.Equal(t, "ACME", got.Domain)
	require.Equal(t, "jsmith", got.User)
	require.Equal(t, "LAPTOP", got.Workstation)
	require.Equal(t, "NTLMv1", got.Version)
	require.Equal(t, 24, got.NTResponseLen)
	require.Len(t, got.NtChallengeResponse, 24)
}

func TestBuildSMBChallenge(t *testing.T) {
	msg := BuildSMBChallenge([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, "SERVER")
	require.True(t, bytes.HasPrefix(msg, signature))
	require.Equal(t, uint32(MsgChallenge), MessageType(msg))
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, msg[24:32])
	flags := binary.LittleEndian.Uint32(msg[20:24])
	require.NotZero(t, flags&FlagUnicode)
	require.NotZero(t, flags&FlagNTLM)
	// TargetNUL: TargetName length includes trailing UTF-16 NUL.
	require.Equal(t, uint16(len("SERVER")*2+2), binary.LittleEndian.Uint16(msg[12:14]))
}

func TestBuildChallengeRich(t *testing.T) {
	now := time.Date(2026, 10, 8, 14, 51, 3, 0, time.UTC)
	msg := BuildChallenge(ChallengeOptions{
		ServerChallenge: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Domain:          "WORKGROUP",
		Computer:        "WIN-ABC123",
		Now:             now,
		RichTargetInfo:  true,
	})
	require.Equal(t, Signature, string(msg[0:8]))
	require.Zero(t, binary.LittleEndian.Uint32(msg[20:24])&FlagVersion)
	require.Equal(t, uint32(48), binary.LittleEndian.Uint32(msg[16:20]))

	withVer := BuildChallenge(ChallengeOptions{
		ServerChallenge: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Domain:          "WORKGROUP",
		Computer:        "WIN-ABC123",
		ClientFlags:     FlagVersion,
		Now:             now,
		RichTargetInfo:  true,
	})
	require.NotZero(t, binary.LittleEndian.Uint32(withVer[20:24])&FlagVersion)
	require.Equal(t, uint32(56), binary.LittleEndian.Uint32(withVer[16:20]))
	require.Equal(t, byte(0x0a), withVer[48])
	require.Equal(t, uint16(17763), binary.LittleEndian.Uint16(withVer[50:52]))
}

func TestFindInWrappedBlob(t *testing.T) {
	msg := BuildSMBChallenge([8]byte{}, "X")
	blob := append([]byte{0x60, 0x40, 0x06, 0x06, 0x2b}, msg...)
	got, ok := Find(blob)
	require.True(t, ok)
	require.Equal(t, msg, got)
	_, ok = Find([]byte("no signature here"))
	require.False(t, ok)
}

func TestSPNEGOTokens(t *testing.T) {
	init := NegTokenInit()
	require.Equal(t, byte(0x60), init[0])
	require.True(t, bytes.Contains(init, OIDNTLMSSP))
	require.True(t, bytes.Contains(init, OIDSPNEGO))

	chal := NegTokenChallenge(BuildSMBChallenge([8]byte{}, "X"))
	require.Equal(t, byte(0xa1), chal[0])
	require.True(t, bytes.Contains(chal, signature))
	ntlm, wrapped := UnwrapSPNEGO(chal)
	require.True(t, wrapped)
	require.Equal(t, Signature, string(ntlm[:8]))

	accept := NegTokenAccept()
	require.Equal(t, byte(0xa1), accept[0])
	require.Contains(t, string(accept), "\x0a\x01\x00")
}

func TestLen(t *testing.T) {
	require.Equal(t, []byte{0x7f}, Len(0x7f))
	require.Equal(t, []byte{0x81, 0x80}, Len(0x80))
	require.Equal(t, []byte{0x82, 0x01, 0x00}, Len(256))
}

func TestToFILETIME(t *testing.T) {
	now := time.Date(2026, 10, 8, 14, 51, 3, 0, time.UTC)
	ft := ToFILETIME(now)
	gotNs := (int64(ft) - FiletimeEpochDiff) * 100
	require.Equal(t, now.UnixNano(), gotNs)
	require.Equal(t, uint64(FiletimeEpochDiff), ToFILETIME(time.Unix(0, 0).UTC()))
}

func TestVersionFromNTLen(t *testing.T) {
	require.Equal(t, "anonymous", VersionFromNTLen(0))
	require.Equal(t, "NTLMv1", VersionFromNTLen(24))
	require.Equal(t, "NTLMv2", VersionFromNTLen(48))
	require.Equal(t, "", VersionFromNTLen(8))
}
