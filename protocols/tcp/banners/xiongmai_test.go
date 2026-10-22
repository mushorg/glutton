package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXiongmaiOpenTelnet(t *testing.T) {
	prev := xmRandNum
	xmRandNum = func() string { return "01234567" }
	t.Cleanup(func() { xmRandNum = prev })

	for _, data := range [][]byte{
		[]byte("OpenTelnet:OpenOnce"),                // Shodan, Ochi live stream 2026-10-22 22:06 UTC, tcp/9530
		append([]byte{19}, "OpenTelnet:OpenOnce"...), // PoC length prefix
		[]byte("OpenTelnet:OpenOnce\x00"),
		[]byte("OpenTelnet:OpenOnce\r\n"),
	} {
		resp, ok := ForPayload(data)
		require.True(t, ok, "%q", data)
		require.Equal(t, Response{Name: "xiongmai-randnum", Data: []byte("randNum:01234567")}, resp)
	}

	for _, data := range [][]byte{
		[]byte("OpenTelnet:Open"),
		[]byte("OpenTelnet:OpenOnce2"),
		append([]byte{5}, "OpenTelnet:OpenOnce"...),
		[]byte(""),
	} {
		_, ok := xiongmaiReply(data)
		require.False(t, ok, "%q", data)
	}
}

func TestXiongmaiRandNum(t *testing.T) {
	for range 20 {
		n := xmRandNum()
		require.Len(t, n, 8)
		require.Regexp(t, `^[0-9]{8}$`, n)
	}
}
