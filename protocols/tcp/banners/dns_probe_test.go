package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanDNSQueryProbe is the 19-byte probe captured on tcp/444 from a
// Shodan-tagged source (143.110.239.2).
var shodanDNSQueryProbe = []byte("HTTP/1.1 GET /dns?\x00")

func TestDNSQueryProbe(t *testing.T) {
	require.Len(t, shodanDNSQueryProbe, 19)
	for _, p := range [][]byte{shodanDNSQueryProbe, []byte("HTTP/1.1 GET /dns?")} {
		resp, ok := ForPayload(p)
		require.True(t, ok)
		require.Equal(t, Response{Name: "dns-query-probe", Silent: true}, resp)
	}

	for name, p := range map[string]string{
		"two nuls":       "HTTP/1.1 GET /dns?\x00\x00",
		"crlf":           "HTTP/1.1 GET /dns?\r\n",
		"with query":     "HTTP/1.1 GET /dns?name=x\x00",
		"real request":   "GET /dns? HTTP/1.1\r\n\r\n",
		"prefix only":    "HTTP/1.1 GET /dns",
		"leading byte":   "xHTTP/1.1 GET /dns?\x00",
		"other path":     "HTTP/1.1 GET /dnsx\x00",
		"http/1.0 first": "HTTP/1.0 GET /dns?\x00",
	} {
		require.False(t, isDNSQueryProbe([]byte(p)), name)
	}
}
