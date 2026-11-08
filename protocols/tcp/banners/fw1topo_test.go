package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForPayloadFW1TopoHello(t *testing.T) {
	// Ochi tcp/264, 207.90.244.27
	resp, ok := ForPayload([]byte{0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21})
	require.True(t, ok)
	require.Equal(t, Response{Name: "fw1-topology-hello", Data: []byte("Y\x00\x00\x00")}, resp)
}

func TestForPayloadFW1TopoSecuRemote(t *testing.T) {
	resp, ok := ForPayload([]byte("\x00\x00\x00\x0bsecuremote\x00"))
	require.True(t, ok)
	require.Equal(t, "fw1-topology-securemote", resp.Name)
	require.True(t, resp.Close)
	dn := "CN=cpgw-edge01,O=cpmgmt01..k7x3qa"
	require.Equal(t, append(append([]byte{0x00, 0x00, 0x00, byte(len(dn) + 1)}, dn...), 0x00), resp.Data)
	// Metasploit's checkpoint_hostname parses CN=(.+),O=.(.+?)\.
	require.Regexp(t, `CN=(.+),O=.(.+?)\.`, string(resp.Data))
}

func TestForPayloadFW1TopoRejects(t *testing.T) {
	for _, data := range [][]byte{
		{0x51, 0x00, 0x00, 0x00},                               // half a hello
		{0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x0a}, // trailing byte
		[]byte("\x00\x00\x00\x0bsecuremote"),                   // no NUL
		[]byte("\x00\x00\x00\x0csecuremote\x00"),               // length mismatch
	} {
		resp, ok := ForPayload(data)
		require.False(t, ok && (resp.Name == "fw1-topology-hello" || resp.Name == "fw1-topology-securemote"), "%x", data)
	}
}

func TestForPortFW1Topo(t *testing.T) {
	resp, ok := ForPort(264)
	require.True(t, ok)
	require.Equal(t, Response{Name: "fw1-topology", Silent: true}, resp)
}
