package rdp

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fixedNow is a stable time used to make AvTimestamp assertions deterministic.
var fixedNow = time.Date(2026, 10, 8, 14, 51, 3, 0, time.UTC)

func TestBuildNTLMChallengeNoVersion(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	opts := NTLMChallengeOptions{
		Computer: "WIN-ABC123",
		Domain:   "WORKGROUP",
		Now:      fixedNow,
		// ClientFlags does NOT set ntlmFlagVersion → payload at offset 48.
	}
	msg := buildNTLMChallenge(challenge, opts)

	// Signature
	require.Equal(t, ntlmSig, string(msg[0:8]))
	// MessageType = 2
	require.Equal(t, uint32(NTLMMsgChallenge), binary.LittleEndian.Uint32(msg[8:12]))
	// ServerChallenge
	require.Equal(t, challenge, msg[24:32])
	// NegotiateFlags must NOT have NEGOTIATE_VERSION
	flags := binary.LittleEndian.Uint32(msg[20:24])
	require.Zero(t, flags&ntlmFlagVersion, "VERSION flag must be absent")
	// TargetName offset must be 48 (no VERSION block)
	require.Equal(t, uint32(48), binary.LittleEndian.Uint32(msg[16:20]))
}

func TestBuildNTLMChallengeWithVersion(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	opts := NTLMChallengeOptions{
		Computer:    "WIN-ABC123",
		Domain:      "WORKGROUP",
		Now:         fixedNow,
		ClientFlags: ntlmFlagVersion, // client requests VERSION
	}
	msg := buildNTLMChallenge(challenge, opts)

	// NegotiateFlags must have NEGOTIATE_VERSION
	flags := binary.LittleEndian.Uint32(msg[20:24])
	require.NotZero(t, flags&ntlmFlagVersion, "VERSION flag must be present")
	// VERSION block at 48–55: Windows 10.0.17763, NTLM rev 15.
	require.Equal(t, byte(0x0a), msg[48], "ProductMajorVersion = 10")
	require.Equal(t, byte(0x00), msg[49], "ProductMinorVersion = 0")
	require.Equal(t, uint16(17763), binary.LittleEndian.Uint16(msg[50:52]), "ProductBuild = 17763")
	require.Equal(t, byte(0x0f), msg[55], "NTLMRevisionCurrent = 15")
	// TargetName offset must be 56 (VERSION block added)
	require.Equal(t, uint32(56), binary.LittleEndian.Uint32(msg[16:20]))
}

func TestBuildAvPairsFullSet(t *testing.T) {
	avp := buildAvPairs("WORKGROUP", "WIN-ABC123", fixedNow)

	// Parse the AvPairs and collect what we see.
	got := map[uint16][]byte{}
	for len(avp) >= 4 {
		id := binary.LittleEndian.Uint16(avp[0:2])
		l := int(binary.LittleEndian.Uint16(avp[2:4]))
		if 4+l > len(avp) {
			break
		}
		got[id] = avp[4 : 4+l]
		avp = avp[4+l:]
		if id == avEOL {
			break
		}
	}

	require.Contains(t, got, uint16(avNbDomainName), "MsvAvNbDomainName")
	require.Contains(t, got, uint16(avNbComputerName), "MsvAvNbComputerName")
	require.Contains(t, got, uint16(avDnsDomainName), "MsvAvDnsDomainName")
	require.Contains(t, got, uint16(avDnsComputerName), "MsvAvDnsComputerName")
	require.Contains(t, got, uint16(avTimestamp), "MsvAvTimestamp")
	require.Contains(t, got, uint16(avEOL), "MsvAvEOL")

	require.Equal(t, utf16LE("WORKGROUP"), got[avNbDomainName])
	require.Equal(t, utf16LE("WIN-ABC123"), got[avNbComputerName])
	require.Equal(t, 8, len(got[avTimestamp]), "Timestamp must be 8 bytes")
}

func TestBuildTSRequestChallengeWithOptions(t *testing.T) {
	resp, err := BuildTSRequestChallengeWith(NTLMChallengeOptions{
		Computer: "WIN-TEST",
		Domain:   "WORKGROUP",
		Now:      fixedNow,
	})
	require.NoError(t, err)
	require.Equal(t, byte(0x30), resp[0], "TSRequest starts with DER SEQUENCE")
	ntlm := negoTokenFromTSRequest(resp)
	require.NotNil(t, ntlm)
	require.Equal(t, ntlmSig, string(ntlm[:8]))
	require.Equal(t, uint32(NTLMMsgChallenge), binary.LittleEndian.Uint32(ntlm[8:12]))
	// TargetName must encode "WORKGROUP".
	targetNameOff := int(binary.LittleEndian.Uint32(ntlm[16:20]))
	targetNameLen := int(binary.LittleEndian.Uint16(ntlm[12:14]))
	require.Equal(t, utf16LE("WORKGROUP"), ntlm[targetNameOff:targetNameOff+targetNameLen])
}

func TestToFILETIME(t *testing.T) {
	// Cross-check: FILETIME = unix_ns/100 + epoch_diff.
	// Verify round-trip: converting back to nanoseconds should recover the unix time.
	ft := toFILETIME(fixedNow)
	gotNs := (int64(ft) - filetimeEpochDiff) * 100
	require.Equal(t, fixedNow.UnixNano(), gotNs, "round-trip must recover the unix nanoseconds")

	// Sanity: FILETIME for 1970-01-01 00:00:00 UTC must equal the epoch diff.
	epoch := time.Unix(0, 0).UTC()
	require.Equal(t, uint64(filetimeEpochDiff), toFILETIME(epoch))
}

// capturedSPNEGONegotiate is the TSRequest from Ochi event
// 9f62fb02-056c-4b1d-9cd5-17a7c51923ec: a Windows-style client sending the
// NTLM Negotiate inside a GSS InitialContextToken / SPNEGO NegTokenInit.
const capturedSPNEGONegotiate = "3059a003020106a1523050304ea04c044a604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a0428" +
	"4e544c4d53535000010000000582" + "08e0" + "00000000000000000000000000000000" + "0a0039380000000f"

func TestParseCredSSPSPNEGONegotiate(t *testing.T) {
	raw, err := hex.DecodeString(capturedSPNEGONegotiate)
	require.NoError(t, err)
	require.Len(t, raw, 91)
	p := ParseCredSSP(raw)
	require.True(t, p.SPNEGO)
	require.Equal(t, NTLMMsgNegotiate, p.NTLMType)
	require.Equal(t, uint32(0xe0088205), p.NegotiateFlags)
}

func TestParseCredSSPRawNTLMIsNotSPNEGO(t *testing.T) {
	msg := make([]byte, 32)
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgNegotiate)
	p := ParseCredSSP(WrapTSRequest(msg))
	require.False(t, p.SPNEGO)
	require.Equal(t, NTLMMsgNegotiate, p.NTLMType)
}

func TestParseCredSSPSPNEGOAuthenticate(t *testing.T) {
	dom, user := utf16LE("ACME"), utf16LE("jsmith")
	msg := make([]byte, 64+len(dom)+len(user))
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgAuthenticate)
	// NtChallengeResponse: 48 bytes of NTLMv2 data at the tail.
	binary.LittleEndian.PutUint16(msg[20:22], 48)
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(dom)))
	binary.LittleEndian.PutUint32(msg[32:36], 64)
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(user)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(64+len(dom)))
	copy(msg[64:], dom)
	copy(msg[64+len(dom):], user)

	p := ParseCredSSP(WrapTSRequest(wrapNegTokenResp(msg)))
	require.True(t, p.SPNEGO)
	require.Equal(t, NTLMMsgAuthenticate, p.NTLMType)
	require.Equal(t, "ACME", p.Domain)
	require.Equal(t, "jsmith", p.Username)
	require.Equal(t, "NTLMv2", p.NTLMVersion)
}

func TestParseCredSSPMalformedSPNEGO(t *testing.T) {
	for _, tok := range [][]byte{
		{0x60},
		{0x60, 0x05, 0x06, 0x03, 0x01, 0x02, 0x03},
		{0xa1, 0x04, 0x30, 0x02, 0xa2, 0x09},
		{0xa1, 0x84, 0xff, 0xff, 0xff, 0xff},
	} {
		require.NotPanics(t, func() { ParseCredSSP(WrapTSRequest(tok)) })
		require.Equal(t, 0, ParseCredSSP(WrapTSRequest(tok)).NTLMType)
	}
}

func TestBuildTSRequestChallengeSPNEGO(t *testing.T) {
	out, err := BuildTSRequestChallengeWith(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow, SPNEGO: true})
	require.NoError(t, err)
	tok := negoTokenFromTSRequest(out)
	require.Equal(t, byte(0xa1), tok[0], "NegTokenResp")
	require.Contains(t, string(tok), string(oidNTLMSSP))
	ntlm, wrapped := unwrapSPNEGO(tok)
	require.True(t, wrapped)
	require.Equal(t, ntlmSig, string(ntlm[:8]))
	require.Equal(t, uint32(NTLMMsgChallenge), binary.LittleEndian.Uint32(ntlm[8:12]))
}

func TestBuildTSRequestError(t *testing.T) {
	require.Equal(t,
		[]byte{0x30, 0x0e, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa4, 0x07, 0x02, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d},
		BuildTSRequestError(StatusLogonFailure))
}

func TestBuildTSRequestChallengeNonce(t *testing.T) {
	out, nonce, err := BuildTSRequestChallengeNonce(NTLMChallengeOptions{Computer: "WIN-TEST", Domain: "WORKGROUP", Now: fixedNow})
	require.NoError(t, err)
	require.Len(t, nonce, 8)
	ntlm, _ := unwrapSPNEGO(negoTokenFromTSRequest(out))
	require.Equal(t, nonce, ntlm[24:32], "nonce is the ServerChallenge field")
}
