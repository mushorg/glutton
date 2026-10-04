package udp

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func raknetOCR1FromEvent() []byte {
	// Ochi event 5ad352e3-f96c-4e67-b75d-a07ed53d8c66: 0x05 + magic + protocol 9 + zero pad to 1024.
	data := make([]byte, 1024)
	data[0] = 0x05
	copy(data[1:], raknetMagic)
	data[1+len(raknetMagic)] = 0x09
	return data
}

func raknetUnconnectedPing() []byte {
	data := make([]byte, 1+8+len(raknetMagic))
	data[0] = 0x01
	copy(data[9:], raknetMagic)
	return data
}

func TestHandleRakNetOCR1(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 44956}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 33079}
	payload := raknetOCR1FromEvent()

	err := HandleRakNet(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "raknet", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedRakNet)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, uint8(0x05), events[0].PacketID)
	require.Equal(t, "OPEN_CONNECTION_REQUEST_1", events[0].PacketName)
	require.Equal(t, "OPEN_CONNECTION_REQUEST_1", events[0].Command)
	require.Equal(t, uint8(9), events[0].Protocol)
	require.True(t, events[0].MagicOK)
	require.Equal(t, 1024, events[0].MTU)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleRakNetUnconnectedPing(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 19132}
	payload := raknetUnconnectedPing()

	err := HandleRakNet(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "raknet", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedRakNet)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, uint8(0x01), events[0].PacketID)
	require.Equal(t, "UNCONNECTED_PING", events[0].PacketName)
	require.True(t, events[0].MagicOK)
	require.Equal(t, uint8(0), events[0].Protocol)
	require.Equal(t, 0, events[0].MTU)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleRakNetMissingMagic(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 19132}
	payload := []byte{0x05, 0x00, 0x01, 0x02, 0x03}

	err := HandleRakNet(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "raknet", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedRakNet)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, uint8(0x05), events[0].PacketID)
	require.Equal(t, "OPEN_CONNECTION_REQUEST_1", events[0].PacketName)
	require.False(t, events[0].MagicOK)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleRakNetUnknownIDWithMagic(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 19132}
	payload := append([]byte{0x99}, raknetMagic...)

	err := HandleRakNet(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedRakNet)
	require.True(t, ok)
	require.Equal(t, uint8(0x99), events[0].PacketID)
	require.Equal(t, "UNKNOWN", events[0].PacketName)
	require.True(t, events[0].MagicOK)
}

func TestHandleUDPPeeksRakNet(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 44956}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 33079}
	payload := raknetOCR1FromEvent()

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "raknet", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedRakNet)
	require.True(t, ok)
	require.Equal(t, "OPEN_CONNECTION_REQUEST_1", events[0].PacketName)
	require.True(t, events[0].MagicOK)
}

func TestLooksLikeRakNet(t *testing.T) {
	require.True(t, looksLikeRakNet(raknetOCR1FromEvent()))
	require.True(t, looksLikeRakNet(raknetUnconnectedPing()))
	require.False(t, looksLikeRakNet(nil))
	require.False(t, looksLikeRakNet([]byte{0x05, 0x00}))
	require.False(t, looksLikeRakNet(bytes.Repeat([]byte{0x00}, 32)))
}
