package banners

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIperf3Cookie(t *testing.T) {
	// nmap iperf3 probe, Shodan on tcp/5201 (2026-11-12, payload hash 8fd286e2...)
	nmapProbe := append(bytes.Repeat([]byte("0"), 37), 0, 0, 0, 0)
	// real iperf3 client cookie: 36 chars of [a-z2-7] and a NUL
	realCookie := append([]byte("abcdefghijklmnopqrstuvwxyz234567abcd"), 0)
	for _, data := range [][]byte{nmapProbe, realCookie, nmapProbe[:37]} {
		resp, ok := ForPayload(data)
		require.True(t, ok, "%q", data)
		require.Equal(t, Response{Name: "iperf3-param-exchange", Data: []byte{0x09}}, resp)
	}

	for _, data := range [][]byte{
		nmapProbe[:36],
		append(append([]byte{}, nmapProbe[:37]...), 0, 0, 0, 1),
		append(append([]byte{}, nmapProbe...), 0),
		append([]byte("abcdefghijklmnopqrstuvwxyz23456 abcd"), 0),
		bytes.Repeat([]byte{0}, 41),
	} {
		_, ok := iperf3Reply(data)
		require.False(t, ok, "%q", data)
	}
}
