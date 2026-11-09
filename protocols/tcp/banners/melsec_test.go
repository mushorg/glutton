package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMelsecCPUInfo(t *testing.T) {
	// Censys, tcp/2103 (run-1794266574-2.jsonl event #1)
	query := mustHex("57000000001111070000ffff030000fe03000014001c080a08000000000000000401010100000000" + "01")
	require.Len(t, query, 41)
	resp, ok := ForPayload(query)
	require.True(t, ok)
	require.Equal(t, "melsec-cpuinfo", resp.Name)
	require.Equal(t, melsecCPUInfo(melsecCPUModel), resp.Data)

	for _, other := range []string{
		"57000000001111070000ffff030000fe03000014001c080a080000000000000004010101000000",
		"d7000000001111070000ffff030000fe03000014001c080a08000000000000000401010100000000" + "01",
	} {
		resp, ok := ForPayload(mustHex(other))
		require.False(t, ok && resp.Name == "melsec-cpuinfo", other)
	}

	data := melsecCPUInfo("Q03UDECPU")
	require.Len(t, data, 60)
	require.Equal(t, byte(0xd7), data[0])
	require.Equal(t, query[1:19], data[1:19])
	require.Equal(t, []byte{39, 0}, data[19:21])
	require.Equal(t, query[21:], data[21:41])
	require.Equal(t, byte(0), data[41])
	// as melsecq-discover reads it: NUL-terminated at 42, cut to 16
	require.Equal(t, "Q03UDECPU       ", cstring(t, data, 42))
}
