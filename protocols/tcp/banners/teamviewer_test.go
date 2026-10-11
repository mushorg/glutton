package banners

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// tvShodanPing is the CMD_PING from Ochi event
// be79fd0e-21f8-4c3e-97f0-93d7b483e819 (drive.census.shodan.io, tcp/5938).
var tvShodanPing = []byte{0x17, 0x24, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}

func TestForPayloadTeamViewerPing(t *testing.T) {
	resp, ok := ForPayload(tvShodanPing)
	require.True(t, ok)
	require.Equal(t, Response{Name: "teamviewer-pingok", Data: []byte{0x17, 0x24, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}}, resp)

	for _, data := range [][]byte{
		tvShodanPing[:5], // body missing
		append(append([]byte(nil), tvShodanPing...), 0x00),     // longer than its length field
		{0x17, 0x24, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, // CMD_PINGOK, not a ping
		{0x11, 0x30, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, // protocol 2.x magic
	} {
		require.False(t, isTVPing(data), "% x", data)
	}
}

func TestForPortTeamViewerIdentify(t *testing.T) {
	prev := tvConnID
	tvConnID = func() [4]byte { return [4]byte{0xde, 0xad, 0xbe, 0xef} }
	t.Cleanup(func() { tvConnID = prev })

	resp, ok := ForPort(5938)
	require.True(t, ok)
	require.Equal(t, "teamviewer-identify", resp.Name)
	require.True(t, resp.GreetWhenIdle)
	require.False(t, resp.ServerFirst)
	require.True(t, resp.Once)

	// the length field covers the body after the 5-byte header
	require.Len(t, resp.Data, 37)
	require.Equal(t, len(resp.Data)-tvHeaderLen, int(binary.LittleEndian.Uint16(resp.Data[3:5])))
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, resp.Data[5:9])

	// fills the wildcard of the nmap-service-probes NULL match for p/TeamViewer/:
	// ^\x17\x24\x0a\x20\x00....\x68\x42\0\0\0\0\0\0\x01\0\0\0\x11\x80\0{14}$
	want := append([]byte{0x17, 0x24, 0x0a, 0x20, 0x00, 0xde, 0xad, 0xbe, 0xef,
		0x68, 0x42, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0x11, 0x80}, make([]byte, 14)...)
	require.Equal(t, want, resp.Data)
}
