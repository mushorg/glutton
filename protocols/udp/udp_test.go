package udp

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestHandleUDPProducesReadFrame(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 33265}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8000}
	payload := bytes.Repeat([]byte{0x5e}, 88)

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedUDP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, payload, events[0].Payload)
	require.NotEmpty(t, events[0].PayloadHash)
	require.False(t, events[0].Truncated)
}

func TestHandleUDPEmptyPayload(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8000}

	err := HandleUDP(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedUDP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Empty(t, events[0].Payload)
}

func TestHandleUDPCapsOversizedPayload(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8000}
	payload := bytes.Repeat([]byte{0xaa}, maxUDPPayload+200)

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Equal(t, payload[:maxUDPPayload], h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedUDP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, payload[:maxUDPPayload], events[0].Payload)
	require.True(t, events[0].Truncated)
	require.NotEmpty(t, events[0].PayloadHash)
}
