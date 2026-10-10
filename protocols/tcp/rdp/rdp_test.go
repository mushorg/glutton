package rdp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func processRawCR(raw string, t *testing.T) ConnectionRequestPDU {
	data, err := hex.DecodeString(raw)
	require.NoError(t, err)

	pdu, err := ParseCRPDU(data)
	require.NoError(t, err)
	return pdu
}

func TestRDPParseHeader1(t *testing.T) {
	raw := "0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000"
	pdu := processRawCR(raw, t)
	if string(pdu.Data) != "Cookie: mstshash=hello" {
		fmt.Printf("%q\n", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data: %+v\n", pdu)
}

func TestRDPParseHeader2(t *testing.T) {
	raw := "0300001f1ae00000000000436f6f6b69653a206d737473686173683d610d0a"
	pdu := processRawCR(raw, t)
	if string(pdu.Data) != "Cookie: mstshash=a" {
		fmt.Printf("%q\n", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data: %+v\n", pdu)
}

func TestConnectionConfirm(t *testing.T) {
	cr := CRTPDU{SrcRef: [2]byte{0x11, 0x22}}
	header, cc, err := ConnectionConfirm(cr, true, ProtocolHybrid)
	require.NoError(t, err)
	// TPKT v3, length 19 | X.224 CC (LI 14, type 0xD0, dst-ref echoes CR src-ref) | RDP_NEG_RSP CredSSP
	require.Equal(t, "030000130ed011220000000200080002000000", hex.EncodeToString(cc))
	require.Equal(t, byte(3), header.Version)
	require.Equal(t, [2]byte{0x00, 0x13}, header.Length)
}

func TestSelectProtocol(t *testing.T) {
	require.Equal(t, ProtocolHybrid, SelectProtocol(0x3))
	require.Equal(t, ProtocolHybrid, SelectProtocol(0xb))
	require.Equal(t, ProtocolSSL, SelectProtocol(0x1))
	require.Equal(t, ProtocolRDP, SelectProtocol(0x0))
	require.Equal(t, ProtocolRDP, SelectProtocol(0x4))
}

func TestRequestedMask(t *testing.T) {
	require.Equal(t, uint32(3), RequestedMask(processRawCR("0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000", t)))
	require.Equal(t, uint32(0), RequestedMask(processRawCR("0300000b06e00000000000", t)))
}

func TestConnectionConfirmStandardRDP(t *testing.T) {
	cr := CRTPDU{SrcRef: [2]byte{0x00, 0x00}}
	header, cc, err := ConnectionConfirm(cr, false, ProtocolRDP)
	require.NoError(t, err)
	require.Equal(t, "0300000b06d00000000000", hex.EncodeToString(cc))
	require.Equal(t, byte(3), header.Version)
	require.Equal(t, [2]byte{0x00, 0x0b}, header.Length)
}

func TestParseCRPDUStandardNoNeg(t *testing.T) {
	pdu := processRawCR("0300000b06e00000000000", t)
	require.Equal(t, byte(TPDUConnectionRequest), pdu.TPDU.ConnectionRequestCode)
	require.False(t, HasRDPNegReq(pdu))
	require.Empty(t, pdu.Data)
}

func TestParseCRPDUNegReqWithoutCookie(t *testing.T) {
	pdu := processRawCR("030000130ee000000000000100080003000000", t)
	require.True(t, HasRDPNegReq(pdu))
	require.Equal(t, byte(0x01), pdu.RDPNegReq.Type)
	require.Equal(t, [4]byte{0x03, 0x00, 0x00, 0x00}, pdu.RDPNegReq.RequestedProtocols)
}

func TestTPDUTypeAndMCS(t *testing.T) {
	cr := mustHex("0300000b06e00000000000")
	require.True(t, IsConnectionRequest(cr))
	require.False(t, IsDataTPDU(cr))
	require.False(t, IsMCSConnectInitial(cr))

	mcs := mustHex("0300019c02f0807f65820190")
	require.True(t, IsDataTPDU(mcs))
	require.True(t, IsMCSConnectInitial(mcs))
	require.False(t, IsConnectionRequest(mcs))
}

func TestMCSConnectResponse(t *testing.T) {
	header, resp := MCSConnectResponse(ProtocolSSL)
	require.Greater(t, len(resp), 11)
	require.Equal(t, byte(3), resp[0])
	require.Equal(t, byte(TPDUData), resp[5])
	require.NotEqual(t, byte(TPDUConnectionConfirm), resp[5])
	require.Equal(t, uint16(len(resp)), binary.BigEndian.Uint16(resp[2:4]))
	require.Equal(t, header.Length, [2]byte{resp[2], resp[3]})
	require.True(t, bytes.Contains(resp, []byte{0x7f, 0x66}))
	require.True(t, bytes.Contains(resp, []byte("McDn")))
	require.False(t, IsMCSConnectInitial(resp))
	// SC_CORE (01 0c 10 00) carries the selected protocol after the version.
	i := bytes.Index(resp, []byte{0x01, 0x0c, 0x10, 0x00})
	require.GreaterOrEqual(t, i, 0)
	require.Equal(t, uint32(ProtocolSSL), binary.LittleEndian.Uint32(resp[i+8:i+12]))
}

func TestIsTSRequest(t *testing.T) {
	require.True(t, IsTSRequest([]byte{0x30, 0x82, 0x01, 0x00}))
	require.False(t, IsTSRequest([]byte{0x03, 0x00, 0x00, 0x0b}))
	require.False(t, IsTSRequest(nil))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestWrapAndExtractTSRequest(t *testing.T) {
	ntlm := make([]byte, 32)
	copy(ntlm[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], NTLMMsgNegotiate)
	wrapped := WrapTSRequest(ntlm)
	require.Equal(t, byte(0x30), wrapped[0], "outer SEQUENCE tag")
	got := negoTokenFromTSRequest(wrapped)
	require.Equal(t, ntlm, got, "round-trip must recover original NTLM bytes")
}

func TestBuildTSRequestChallenge(t *testing.T) {
	resp, err := BuildTSRequestChallenge()
	require.NoError(t, err)
	require.Equal(t, byte(0x30), resp[0], "TSRequest starts with DER SEQUENCE")
	ntlm := negoTokenFromTSRequest(resp)
	require.NotNil(t, ntlm)
	require.Equal(t, ntlmSig, string(ntlm[:8]))
	require.Equal(t, uint32(NTLMMsgChallenge), binary.LittleEndian.Uint32(ntlm[8:12]))
}

func TestParseCredSSPNegotiate(t *testing.T) {
	ntlm := make([]byte, 32)
	copy(ntlm[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], NTLMMsgNegotiate)
	binary.LittleEndian.PutUint32(ntlm[12:16], 0x00003207)
	parsed := ParseCredSSP(WrapTSRequest(ntlm))
	require.Equal(t, NTLMMsgNegotiate, parsed.NTLMType)
	require.Empty(t, parsed.Domain)
	require.Empty(t, parsed.Username)
}

func TestParseCredSSPAuthenticate(t *testing.T) {
	domain := "ACME"
	username := "jsmith"
	domBytes := utf16LE(domain)
	userBytes := utf16LE(username)
	payloadOff := 56 // minimal header: 8+4+8+8+8+8+8+4 = 56, no optional fields
	domOff := payloadOff
	userOff := payloadOff + len(domBytes)
	total := userOff + len(userBytes)
	ntlm := make([]byte, total)
	copy(ntlm[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], NTLMMsgAuthenticate)
	// DomainNameFields at 28
	binary.LittleEndian.PutUint16(ntlm[28:30], uint16(len(domBytes)))
	binary.LittleEndian.PutUint16(ntlm[30:32], uint16(len(domBytes)))
	binary.LittleEndian.PutUint32(ntlm[32:36], uint32(domOff))
	// UserNameFields at 36
	binary.LittleEndian.PutUint16(ntlm[36:38], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(ntlm[38:40], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(ntlm[40:44], uint32(userOff))
	copy(ntlm[domOff:], domBytes)
	copy(ntlm[userOff:], userBytes)

	parsed := ParseCredSSP(WrapTSRequest(ntlm))
	require.Equal(t, NTLMMsgAuthenticate, parsed.NTLMType)
	require.Equal(t, domain, parsed.Domain)
	require.Equal(t, username, parsed.Username)
}

func TestParseCredSSPNoNegoTokens(t *testing.T) {
	// TSRequest with only a version field (no negoTokens).
	tsReq := []byte{0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x06}
	parsed := ParseCredSSP(tsReq)
	require.Equal(t, 0, parsed.NTLMType)
	require.Empty(t, parsed.Domain)
}

func TestParseCredSSPMalformed(t *testing.T) {
	require.Equal(t, ParsedCredSSP{}, ParseCredSSP(nil))
	require.Equal(t, ParsedCredSSP{}, ParseCredSSP([]byte{0xff}))
	require.Equal(t, ParsedCredSSP{}, ParseCredSSP([]byte{0x30, 0x01, 0x00}))
}

func TestParseCredSSPNegotiateFlags(t *testing.T) {
	ntlm := make([]byte, 32)
	copy(ntlm[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:12], NTLMMsgNegotiate)
	binary.LittleEndian.PutUint32(ntlm[12:16], 0x60088235)
	parsed := ParseCredSSP(WrapTSRequest(ntlm))
	require.Equal(t, NTLMMsgNegotiate, parsed.NTLMType)
	require.Equal(t, uint32(0x60088235), parsed.NegotiateFlags)
}

func TestLooksLikeConnectionRequest(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want bool
	}{
		// Ochi event 325c8103-b64a-4aeb-a2a3-3a8c9c32e05c, tcp/49119
		{"cookie Administr", "0300002f2ae00000000000436f6f6b69653a206d737473686173683d41646d696e697374720d0a0100080003000000", true},
		{"cookie hello", "0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000", true},
		{"bare CR", "0300000b06e00000000000", true},
		{"header only", "0300002f2ae0", true},
		{"too short", "0300002f2a", false},
		{"tls", "160301020001", false},
		{"http", "474554202f20", false},
		{"x224 data", "0300000c02f0807f6582", false},
		{"LI mismatch", "0300002f26e00000000000", false},
		{"length too small", "0300000a05e000000000", false},
		{"length too large", "030004012fe0", false},
		{"tpkt version", "0200002f2ae00000000000", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := hex.DecodeString(test.hex)
			require.NoError(t, err)
			require.Equal(t, test.want, LooksLikeConnectionRequest(data))
		})
	}
}
