package udp

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Captured Censys discovery probe (Ochi event 2aa6e947-f427-4454-9776-3f34171ac06f).
func steamCapturedDiscovery(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("ffffffff214c5fa00a000000089acc97eea3cd021000020000000800")
	require.NoError(t, err)
	return b
}

func steamAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 16622},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 27036}
}

func TestHandleSteamDiscovery(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()
	payload := steamCapturedDiscovery(t)

	require.NoError(t, HandleSteam(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "steam", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies, "parse-only: a Status reply would be larger than the probe")

	events, ok := h.produced[0].decoded.([]parsedSteam)
	require.True(t, ok)
	require.Equal(t, []parsedSteam{
		{Direction: "read", Command: "discovery", ClientID: "11451419190810", Payload: payload},
	}, events)
}

func TestHandleSteamDiscoveryWithSequence(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()
	payload, err := hex.DecodeString("ffffffff214c5fa004000000080110000200000008" + "07")
	require.NoError(t, err)

	require.NoError(t, HandleSteam(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSteam)
	require.Equal(t, []parsedSteam{
		{Direction: "read", Command: "discovery", ClientID: "1", SequenceNum: 7, Payload: payload},
	}, events)
}

func TestHandleSteamOtherMessageType(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()
	// device_authorization_request (3)
	payload, err := hex.DecodeString("ffffffff214c5fa004000000080110030000000" + "0")
	require.NoError(t, err)

	require.NoError(t, HandleSteam(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSteam)
	require.Equal(t, []parsedSteam{
		{Direction: "read", Command: "device_authorization_request", ClientID: "1", MsgType: 3, Payload: payload},
	}, events)
}

func TestHandleSteamMalformed(t *testing.T) {
	src, dst := steamAddrs()
	full := steamCapturedDiscovery(t)
	for name, tc := range map[string]struct {
		payload  []byte
		clientID string
		command  string
	}{
		"magic only":     {full[:8], "", "UNKNOWN"},
		"short header":   {full[:14], "", "UNKNOWN"},
		"missing body":   {full[:22], "11451419190810", "discovery"},
		"truncated body": {full[:26], "11451419190810", "discovery"},
	} {
		t.Run(name, func(t *testing.T) {
			h := &recordingHoneypot{}
			require.NoError(t, HandleSteam(context.Background(), src, dst, tc.payload, connection.Metadata{}, testLogger{}, h))
			require.Len(t, h.produced, 1)
			require.Equal(t, "steam", h.produced[0].handler)
			require.Empty(t, h.replies)
			events := h.produced[0].decoded.([]parsedSteam)
			require.Len(t, events, 1)
			require.Equal(t, tc.payload, events[0].Payload)
			require.Equal(t, tc.command, events[0].Command)
			require.Equal(t, tc.clientID, events[0].ClientID)
		})
	}
}

func TestHandleSteamEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()
	require.NoError(t, HandleSteam(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.produced[0].decoded.([]parsedSteam))
}

func TestHandleSteamCapsOversizePayload(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()
	payload := append(steamCapturedDiscovery(t), bytes.Repeat([]byte{0x41}, 2000)...)

	require.NoError(t, HandleSteam(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSteam)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxSteamPayload)
}

func TestHandleUDPReroutesSteam(t *testing.T) {
	h := &recordingHoneypot{}
	src, _ := steamAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 4242}

	require.NoError(t, HandleUDP(context.Background(), src, dst, steamCapturedDiscovery(t), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "steam", h.produced[0].handler)
}

func TestHandleUDPKeepsNonSteam(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := steamAddrs()

	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("ffff hello"), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
}
