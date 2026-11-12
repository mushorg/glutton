package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSmartInstall(t *testing.T) {
	// 216.25.90.13 -> tcp/4786 (run-1794504358-1.jsonl event #3)
	probe := mustHex("00000001" + "00000001" + "00000004" + "00000008" + "00000001" + "00000000")
	resp, ok := ForPayload(probe)
	require.True(t, ok)
	require.Equal(t, "smart-install", resp.Name)
	// the reply smi_check.py treats as an exposed Smart Install client
	require.Equal(t, mustHex("00000004"+"00000000"+"00000003"+"00000008"+"00000001"+"00000000"), resp.Data)
	require.Len(t, resp.Data, 24)

	for _, other := range []string{
		"0000000100000001000000040000000800000001",
		"00000001000000010000000400000008000000010000000000",
		"000000040000000000000003000000080000000100000000",
	} {
		resp, ok := ForPayload(mustHex(other))
		require.False(t, ok && resp.Name == "smart-install", other)
	}
}
