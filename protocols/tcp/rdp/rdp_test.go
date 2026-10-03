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
	header, cc, err := ConnectionConfirm(cr, true)
	require.NoError(t, err)
	// TPKT v3, length 19 | X.224 CC (LI 14, type 0xD0, dst-ref echoes CR src-ref) | RDP_NEG_RSP TLS|CredSSP
	require.Equal(t, "030000130ed011220000000200080003000000", hex.EncodeToString(cc))
	require.Equal(t, byte(3), header.Version)
	require.Equal(t, [2]byte{0x00, 0x13}, header.Length)
}

func TestConnectionConfirmStandardRDP(t *testing.T) {
	cr := CRTPDU{SrcRef: [2]byte{0x00, 0x00}}
	header, cc, err := ConnectionConfirm(cr, false)
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
	header, resp := MCSConnectResponse()
	require.Greater(t, len(resp), 11)
	require.Equal(t, byte(3), resp[0])
	require.Equal(t, byte(TPDUData), resp[5])
	require.NotEqual(t, byte(TPDUConnectionConfirm), resp[5])
	require.Equal(t, uint16(len(resp)), binary.BigEndian.Uint16(resp[2:4]))
	require.Equal(t, header.Length, [2]byte{resp[2], resp[3]})
	require.True(t, bytes.Contains(resp, []byte{0x7f, 0x66}))
	require.True(t, bytes.Contains(resp, []byte("McDn")))
	require.False(t, IsMCSConnectInitial(resp))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
