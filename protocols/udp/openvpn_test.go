package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func openVPNHardResetInternet() []byte {
	// opcode 7 (P_CONTROL_HARD_RESET_CLIENT_V2), key_id 0, session ID "internet"
	return []byte{0x38, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't', 0, 0, 0, 0, 0}
}

func TestHandleOpenVPNHardReset(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 61611}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := openVPNHardResetInternet()

	err := HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedOpenVPN)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, uint8(7), events[0].Opcode)
	require.Equal(t, "P_CONTROL_HARD_RESET_CLIENT_V2", events[0].OpcodeName)
	require.Equal(t, uint8(0), events[0].KeyID)
	require.Equal(t, "696e7465726e6574", events[0].SessionID)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleOpenVPNShortPacket(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := []byte{0x38}

	err := HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedOpenVPN)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, uint8(7), events[0].Opcode)
	require.Equal(t, "P_CONTROL_HARD_RESET_CLIENT_V2", events[0].OpcodeName)
	require.Equal(t, uint8(0), events[0].KeyID)
	require.Empty(t, events[0].SessionID)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleOpenVPNEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}

	err := HandleOpenVPN(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Empty(t, h.replies)
}

func TestParseOpenVPNHeaderUnknownOpcode(t *testing.T) {
	frame := parseOpenVPNHeader([]byte{0xf8, 1, 2, 3, 4, 5, 6, 7, 8})
	require.Equal(t, uint8(31), frame.Opcode)
	require.Equal(t, "UNKNOWN", frame.OpcodeName)
	require.Equal(t, uint8(0), frame.KeyID)
	require.Equal(t, "0102030405060708", frame.SessionID)
}
