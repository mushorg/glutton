package rdp

import (
	"encoding/binary"
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
