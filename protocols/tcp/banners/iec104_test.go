package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForPayloadIEC104TestFr(t *testing.T) {
	// Shodan (eggs.scanf.shodan.io), tcp/2404: TESTFR act
	resp, ok := ForPayload([]byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00})
	require.True(t, ok)
	require.Equal(t, Response{
		Name: "iec104-testfr",
		Data: []byte{0x68, 0x04, 0x83, 0x00, 0x00, 0x00},
	}, resp)
}

func TestForPayloadIEC104Pipelined(t *testing.T) {
	// STARTDT act then TESTFR act in one read
	resp, ok := ForPayload([]byte{
		0x68, 0x04, 0x07, 0x00, 0x00, 0x00,
		0x68, 0x04, 0x43, 0x00, 0x00, 0x00,
	})
	require.True(t, ok)
	require.Equal(t, Response{
		Name: "iec104-startdt",
		Data: []byte{
			0x68, 0x04, 0x0b, 0x00, 0x00, 0x00,
			0x68, 0x04, 0x83, 0x00, 0x00, 0x00,
		},
	}, resp)

	resp, ok = ForPayload([]byte{0x68, 0x04, 0x13, 0x00, 0x00, 0x00})
	require.True(t, ok)
	require.Equal(t, "iec104-stopdt", resp.Name)
	require.Equal(t, []byte{0x68, 0x04, 0x23, 0x00, 0x00, 0x00}, resp.Data)
}

func TestForPayloadIEC104Confirmation(t *testing.T) {
	resp, ok := ForPayload([]byte{0x68, 0x04, 0x83, 0x00, 0x00, 0x00})
	require.True(t, ok)
	require.Equal(t, Response{Name: "iec104", NoReply: true}, resp)
}

func TestForPayloadIEC104Rejects(t *testing.T) {
	for _, data := range [][]byte{
		{0x68, 0x04, 0x43, 0x00, 0x00},                         // short
		{0x68, 0x04, 0x43, 0x00, 0x00, 0x00, 0x0a},             // trailing byte
		{0x68, 0x05, 0x43, 0x00, 0x00, 0x00},                   // wrong length
		{0x68, 0x04, 0x43, 0x00, 0x01, 0x00},                   // nonzero control
		{0x68, 0x04, 0x01, 0x00, 0x00, 0x00},                   // S-format
		{0x68, 0x04, 0x03, 0x00, 0x00, 0x00},                   // two functions
		{0x68, 0x04, 0x43, 0x00, 0x00, 0x00, 0x68, 0x0e, 0x00}, // I-frame follows
	} {
		resp, ok := ForPayload(data)
		require.False(t, ok && len(resp.Name) >= 6 && resp.Name[:6] == "iec104", "%x", data)
	}
}

func TestForPortIEC104(t *testing.T) {
	resp, ok := ForPort(2404)
	require.True(t, ok)
	require.Equal(t, Response{Name: "iec104", NoReply: true}, resp)
}
