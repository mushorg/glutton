package banners

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// lzrTNSConnect is the LZR Oracle probe from Ochi event
// 0120c865-1ddd-4a2d-aa00-ad87334839cc (tcp/3309).
func lzrTNSConnect(t *testing.T) []byte {
	t.Helper()
	header, err := hex.DecodeString(
		"006d0000010000000138012c0c412000ffff7f08000001000033003a00000800" +
			"4141" + "000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	return append(header, "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=lzrORA))))"...)
}

func TestTNSConnect(t *testing.T) {
	probe := lzrTNSConnect(t)
	require.Len(t, probe, 109)
	require.True(t, isTNSConnect(probe))

	resp, ok := ForPayload(probe)
	require.True(t, ok)
	require.Equal(t, "tns-refuse", resp.Name)
	require.True(t, resp.Close)

	want := append([]byte{0x00, 0x67, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x5b},
		"(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=12504)(ERROR_STACK=(ERROR=(CODE=12504)(EMFI=4))))"...)
	require.Equal(t, want, resp.Data)
	require.Equal(t, len(resp.Data), int(binary.BigEndian.Uint16(resp.Data[0:2])))
}

func TestTNSConnectRejects(t *testing.T) {
	mutate := func(f func(b []byte) []byte) []byte {
		return f(lzrTNSConnect(t))
	}
	for name, data := range map[string][]byte{
		"empty":          nil,
		"short header":   lzrTNSConnect(t)[:20],
		"truncated":      lzrTNSConnect(t)[:100],
		"not connect":    mutate(func(b []byte) []byte { b[4] = 0x06; return b }),
		"old version":    mutate(func(b []byte) []byte { b[8], b[9] = 0x00, 0x10; return b }),
		"compat > ver":   mutate(func(b []byte) []byte { b[10], b[11] = 0x01, 0x3f; return b }),
		"data past end":  mutate(func(b []byte) []byte { b[25] = 0x40; return b }),
		"offset in hdr":  mutate(func(b []byte) []byte { b[27] = 0x10; return b }),
		"no descriptor":  mutate(func(b []byte) []byte { b[0x3a] = 'X'; return b }),
		"zero data len":  mutate(func(b []byte) []byte { b[24], b[25] = 0, 0; return b }),
		"length too big": mutate(func(b []byte) []byte { b[1] = 0xff; return b }),
		"random":         []byte("\x00\x6d\x00\x00\x01lol random bytes that are not tns at all"),
	} {
		require.False(t, isTNSConnect(data), name)
		if resp, ok := ForPayload(data); ok {
			require.NotEqual(t, "tns-refuse", resp.Name, name)
		}
	}
}
