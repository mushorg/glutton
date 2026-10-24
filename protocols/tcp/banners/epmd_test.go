package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForPayloadEPMDNames(t *testing.T) {
	// Shodan (cereal.scanf.shodan.io) and nmap's epmd probe, tcp/4369
	resp, ok := ForPayload([]byte{0x00, 0x01, 0x6e})
	require.True(t, ok)
	require.Equal(t, Response{
		Name:  "epmd-names",
		Data:  append([]byte{0x00, 0x00, 0x11, 0x11}, "name rabbit at port 25672\n"...),
		Close: true,
	}, resp)
}

func TestForPayloadEPMDPortPlease(t *testing.T) {
	resp, ok := ForPayload(append([]byte{0x00, 0x07, 'z'}, "rabbit"...))
	require.True(t, ok)
	require.Equal(t, "epmd-port2", resp.Name)
	require.True(t, resp.Close)
	require.Equal(t, append([]byte{
		'w', 0x00, // PORT2_RESP, result ok
		0x64, 0x48, // port 25672
		77, 0x00, // normal node, TCP/IPv4
		0x00, 0x06, 0x00, 0x05, // highest, lowest version
		0x00, 0x06, // name length
	}, append([]byte("rabbit"), 0x00, 0x00)...), resp.Data)

	resp, ok = ForPayload(append([]byte{0x00, 0x05, 'z'}, "ejab"...))
	require.True(t, ok)
	require.Equal(t, []byte{'w', 0x01}, resp.Data)
}

func TestForPayloadEPMDRejects(t *testing.T) {
	for _, data := range [][]byte{
		{0x00, 0x01, 0x6e, 0x0a},                     // trailing byte
		{0x00, 0x02, 0x6e},                           // length mismatch
		append([]byte{0x00, 0x09, 'z'}, "rabbit"...), // length mismatch
		{0x00, 0x01, 'z'},                            // no name
		append([]byte{0x00, 0x04, 'z'}, "a b"...),    // space in name
	} {
		resp, ok := ForPayload(data)
		require.False(t, ok && (resp.Name == "epmd-names" || resp.Name == "epmd-port2"), "%x", data)
	}
}

func TestForPortEPMD(t *testing.T) {
	resp, ok := ForPort(4369)
	require.True(t, ok)
	require.Equal(t, Response{Name: "epmd", Silent: true}, resp)
}
