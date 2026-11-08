package banners

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// cstring reads the NUL-terminated string at off, as nmap's
// codesys-v2-discover does.
func cstring(t *testing.T, data []byte, off int) string {
	t.Helper()
	end := bytes.IndexByte(data[off:], 0)
	require.GreaterOrEqual(t, end, 0)
	return string(data[off : off+end])
}

func TestCodesysDiscovery(t *testing.T) {
	for _, port := range []uint16{1200, 2455} {
		resp, ok := ForPort(port)
		require.True(t, ok)
		require.Equal(t, Response{Name: "codesys", Silent: true}, resp)
	}

	// Shodan, tcp/1200 (run-1794142122-2.jsonl event #8), and the
	// big-endian variant nmap retries with
	for _, query := range []string{"bbbb0100000001", "bbbb0100000101"} {
		resp, ok := ForPayload(mustHex(query))
		require.True(t, ok, query)
		require.Equal(t, "codesys-info", resp.Name)
		require.Equal(t, codesysInfo(codesysRuntime), resp.Data)
	}

	for _, other := range []string{"bbbb01000000", "bbbb010000000100", "bbbb0200000001"} {
		resp, ok := ForPayload(mustHex(other))
		require.False(t, ok && resp.Name == "codesys-info", other)
	}

	id := codesysIdentity{osName: "Nucleus PLUS", osType: "Nucleus PLUS version unknown", product: "3S-Smart Software Solutions"}
	data := codesysInfo(id)
	require.Len(t, data, 160)
	require.Equal(t, []byte{0xbb, 0xbb}, data[:2])
	require.Equal(t, "Nucleus PLUS", cstring(t, data, 64))
	require.Equal(t, "Nucleus PLUS version unknown", cstring(t, data, 96))
	require.Equal(t, "3S-Smart Software Solutions", cstring(t, data, 128))

	long := codesysInfo(codesysIdentity{osName: string(bytes.Repeat([]byte("x"), 40))})
	require.Len(t, cstring(t, long, 64), 31)
}

func TestCodesysPersonas(t *testing.T) {
	require.Contains(t, codesysPersonas, codesysRuntime)
	for _, p := range codesysPersonas {
		require.Less(t, len(p.osName), codesysFieldLen)
		require.Less(t, len(p.osType), codesysFieldLen)
		require.Less(t, len(p.product), codesysFieldLen)
	}
}
