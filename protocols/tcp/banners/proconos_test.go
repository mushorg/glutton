package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProConOSInfo(t *testing.T) {
	// 148.153.189.62, tcp/20547 (run-1794169144-1.jsonl event #8)
	resp, ok := ForPayload(mustHex("cc01000b4002000047ee"))
	require.True(t, ok)
	require.Equal(t, "proconos-info", resp.Name)
	require.Equal(t, proconosInfo(), resp.Data)
	require.False(t, resp.ServerFirst)

	for _, other := range []string{"cc01000b4002000047", "cc01000b4002000047eeff", "cd01000b4002000047ee"} {
		resp, ok := ForPayload(mustHex(other))
		require.False(t, ok && resp.Name == "proconos-info", other)
	}

	data := proconosInfo()
	require.Len(t, data, 99)
	require.Equal(t, []byte{0xcc, 0x01, 0x00, 99, 0x40, 0x02, 0x92, 0x00}, data[:8])
	require.Equal(t, "V3.0", string(data[8:12]))
	require.Equal(t, "ProConOS V3.0.1040 Oct 29 2002", cstring(t, data, 12))
	require.Equal(t, "ILC 350 ETH", cstring(t, data, 44))
	require.Equal(t, "MAINPRO", cstring(t, data, 77))
	require.Equal(t, "MAINPRO", cstring(t, data, 85))
	require.Equal(t, "Exist", cstring(t, data, 93))
	require.Equal(t, byte(0), data[len(data)-1])
}
