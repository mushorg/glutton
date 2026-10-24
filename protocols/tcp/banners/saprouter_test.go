package banners

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shodanRouterAdm is the 35-byte ROUTER_ADM info request Shodan
// (garden.census.shodan.io) sent to tcp/3299 without the NI length prefix.
var shodanRouterAdm = append([]byte("ROUTER_ADM\x00\x02\x02"), make([]byte, 22)...)

func fixSaprouter(t *testing.T) {
	t.Helper()
	prevNow, prevHost := now, saprouterHost
	now = func() time.Time { return time.Date(2026, 10, 24, 17, 54, 39, 0, time.UTC) }
	saprouterHost = "saprouter07"
	t.Cleanup(func() { now, saprouterHost = prevNow, prevHost })
}

// requireNIRouterError checks the NI_RTERR framing: both length fields cover
// what follows them.
func requireNIRouterError(t *testing.T, pkt []byte, rc int32) string {
	t.Helper()
	require.Equal(t, uint32(len(pkt)-4), binary.BigEndian.Uint32(pkt))
	require.Equal(t, "NI_RTERR\x00\x02\x00\x00", string(pkt[4:16]))
	require.Equal(t, rc, int32(binary.BigEndian.Uint32(pkt[16:20])))
	textLen := binary.BigEndian.Uint32(pkt[20:24])
	require.Equal(t, int(textLen), len(pkt)-24-4)
	require.Equal(t, []byte{0, 0, 0, 0}, pkt[len(pkt)-4:])
	return string(pkt[24 : 24+textLen])
}

func TestForPayloadSaprouter(t *testing.T) {
	fixSaprouter(t)
	resp, ok := ForPayload(shodanRouterAdm)
	require.True(t, ok)
	require.Equal(t, "saprouter-too-big", resp.Name)
	require.True(t, resp.Close)
	text := requireNIRouterError(t, resp.Data, -93)
	// "ROUT" read as the NI length
	require.Equal(t, "*ERR*\x001\x00Network packet too big\x00-93\x00NI (network interface)\x00753\x0040\x00nibuf.cpp\x004022\x00"+
		"NiBufIIn: message length 1380930900 exceeds max (10024)\x00Sat Oct 24 17:54:39 2026\x00\x00\x00\x00"+
		"1\x00SAProuter 40.4 (SP3) on 'saprouter07'\x00\x00\x00\x00\x00*ERR*\x00", text)

	for _, data := range [][]byte{[]byte("NI_PING\x00"), []byte("NI_ROUTE\x00\x02\x27")} {
		resp, ok := ForPayload(data)
		require.True(t, ok, "%q", data)
		require.Equal(t, "saprouter-too-big", resp.Name)
	}
	resp, ok = ForPayload([]byte("ROUTER_ADM"))
	require.False(t, ok && resp.Name == "saprouter-too-big")
}

func TestForPortSaprouter(t *testing.T) {
	fixSaprouter(t)
	resp, ok := ForPort(3299)
	require.True(t, ok)
	require.Equal(t, "saprouter-timeout", resp.Name)
	require.True(t, resp.GreetWhenIdle)
	require.True(t, resp.Close)
	require.False(t, resp.ServerFirst)
	text := requireNIRouterError(t, resp.Data, -5)
	require.True(t, strings.HasPrefix(text, "*ERR*\x001\x00connection timed out\x00-5\x00NI (network interface)\x00"), text)
	require.Contains(t, text, "\x00RTPENDLIST::timeoutPend: no route received within 5s (CONNECTED)\x00")
	// nmap's match lines need one-byte lengths
	require.Less(t, len(resp.Data), 256+4)
}
