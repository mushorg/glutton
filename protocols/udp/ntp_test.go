package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func ntpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("174.138.53.53"), Port: 60803},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 123}
}

func ntpMonlist() []byte {
	return append([]byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}, make([]byte, 184)...)
}

func TestHandleNTPMonlist(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ntpAddrs()
	data := ntpMonlist()

	require.NoError(t, HandleNTP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "ntp", h.produced[0].handler)
	require.Equal(t, data, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(data))

	events, ok := h.produced[0].decoded.([]parsedNTP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, parsedNTP{
		Direction: "read", Command: "mon_getlist_1", Version: 2, Mode: 7,
		Implementation: 3, RequestCode: 42, Payload: data,
	}, events[0])
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "error", events[1].Status)
	require.Equal(t, h.replies[0], events[1].Payload)
}

func TestHandleNTPClient(t *testing.T) {
	ntpNow = func() time.Time { return time.Unix(1_700_000_000, 0) }
	t.Cleanup(func() { ntpNow = time.Now })
	h := &recordingHoneypot{}
	src, dst := ntpAddrs()
	req := make([]byte, 48)
	req[0] = 0x23 // VN 4 mode 3

	require.NoError(t, HandleNTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedNTP)
	require.Len(t, events, 2)
	require.Equal(t, "client", events[0].Command)
	require.Equal(t, "server", events[1].Status)
	require.Equal(t, 4, events[1].Mode)
	require.Len(t, h.replies, 1)
	require.Len(t, h.replies[0], 48)
}

func TestHandleNTPMalformed(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ntpAddrs()
	short := []byte{0x17, 0x00}

	require.NoError(t, HandleNTP(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedNTP)
	require.Equal(t, []parsedNTP{{Direction: "read", Command: "unknown", Payload: short}}, events)
}

func TestHandleNTPOversizeTruncated(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ntpAddrs()
	data := append(ntpMonlist(), make([]byte, 2000)...)

	require.NoError(t, HandleNTP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedNTP)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxNTPPayload)
}

func TestHandleUDPRoutesNTP(t *testing.T) {
	h := &recordingHoneypot{}
	src, _ := ntpAddrs()
	other := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9999}

	require.NoError(t, HandleUDP(context.Background(), src, other, ntpMonlist(), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "ntp", h.produced[0].handler)

	h2 := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, other, []byte("hello world"), connection.Metadata{}, testLogger{}, h2))
	require.Equal(t, "udp", h2.produced[0].handler)
}
