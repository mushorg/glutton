package udp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/wsd"
	"github.com/stretchr/testify/require"
)

func wsdAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 50802},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3702}
}

func withWSDState(t *testing.T) *time.Time {
	t.Helper()
	prevLimiter, prevNow := wsdReplies, wsdNow
	now := time.Date(2026, 10, 7, 19, 10, 29, 0, time.UTC)
	wsdReplies = &wsdLimiter{last: map[string]time.Time{}}
	wsdNow = func() time.Time { return now }
	t.Cleanup(func() { wsdReplies, wsdNow = prevLimiter, prevNow })
	return &now
}

func TestHandleWSDiscoveryProbe(t *testing.T) {
	require.Len(t, wsdCapturedProbe, 628)
	withWSDState(t)
	h := &recordingHoneypot{}
	src, dst := wsdAddrs()

	require.NoError(t, HandleWSDiscovery(context.Background(), src, dst, wsdCapturedProbe, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "wsdiscovery", h.produced[0].handler)
	require.Equal(t, wsdCapturedProbe, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	m, err := wsd.Parse(wsdCapturedProbe)
	require.NoError(t, err)
	want, _ := wsd.BuildMatches(m, "198.51.100.1")
	require.Equal(t, [][]byte{want}, h.replies)

	require.Equal(t, []parsedWSD{
		{Direction: "read", Command: "Probe", MessageID: "urn:uuid:ce04dad0-5d2c-4026-9146-1aabfc1e4111", Types: "wsdp:Device", Payload: wsdCapturedProbe},
		{Direction: "write", Command: "Probe", Status: "ProbeMatches", Payload: want},
	}, h.produced[0].decoded.([]parsedWSD))
}

func TestHandleWSDiscoveryRateLimited(t *testing.T) {
	now := withWSDState(t)
	h := &recordingHoneypot{}
	src, dst := wsdAddrs()
	for i := 0; i < 2; i++ {
		require.NoError(t, HandleWSDiscovery(context.Background(), src, dst, wsdCapturedProbe, connection.Metadata{}, testLogger{}, h))
	}
	require.Len(t, h.replies, 1)
	require.Len(t, h.produced[1].decoded.([]parsedWSD), 1)

	*now = now.Add(2 * wsdReplyInterval)
	require.NoError(t, HandleWSDiscovery(context.Background(), src, dst, wsdCapturedProbe, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 2)
}

func TestHandleWSDiscoveryMalformed(t *testing.T) {
	withWSDState(t)
	h := &recordingHoneypot{}
	src, dst := wsdAddrs()
	bad := []byte(`<x xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><unclosed`)

	require.NoError(t, HandleWSDiscovery(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedWSD{{Direction: "read", Command: "UNKNOWN", Payload: bad}}, h.produced[0].decoded.([]parsedWSD))
}

func TestHandleWSDiscoveryOversize(t *testing.T) {
	withWSDState(t)
	h := &recordingHoneypot{}
	src, dst := wsdAddrs()
	big := append(append([]byte{}, wsdCapturedProbe...), []byte(strings.Repeat(" ", 2*maxWSDPayload))...)

	require.NoError(t, HandleWSDiscovery(context.Background(), src, dst, big, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedWSD)
	require.Len(t, events[0].Payload, maxWSDPayload)
	require.True(t, events[0].Truncated)
}

func TestGenericUDPReroutesWSDiscovery(t *testing.T) {
	withWSDState(t)
	h := &recordingHoneypot{}
	src, dst := wsdAddrs()
	dst.Port = 12345
	require.NoError(t, HandleUDP(context.Background(), src, dst, wsdCapturedProbe, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "wsdiscovery", h.produced[0].handler)

	h2 := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("<html>hi</html>"), connection.Metadata{}, testLogger{}, h2))
	require.Equal(t, "udp", h2.produced[0].handler)
}
