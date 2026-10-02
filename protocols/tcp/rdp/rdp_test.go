package rdp

import (
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
	header, cc, err := ConnectionConfirm(cr)
	require.NoError(t, err)
	// TPKT v3, length 19 | X.224 CC (LI 14, type 0xD0, dst-ref echoes CR src-ref) | RDP_NEG_RSP TLS|CredSSP
	require.Equal(t, "030000130ed011220000000200080003000000", hex.EncodeToString(cc))
	require.Equal(t, byte(3), header.Version)
	require.Equal(t, [2]byte{0x00, 0x13}, header.Length)
}

/*
   |e: mstshash=a..|
*/
