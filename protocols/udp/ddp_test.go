package udp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/ddp"
	"github.com/stretchr/testify/require"
)

// Captured SRCH probe (Ochi event f2eae484-8a2a-43b7-95b0-f084c2b6232c).
var ddpCapturedSearch = []byte("SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n")

func ddpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 5855},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 987}
}

// withDDPState gives the test a fresh reply limiter and a controllable clock.
func withDDPState(t *testing.T) *time.Time {
	t.Helper()
	prevLimiter, prevNow := ddpReplies, ddpNow
	now := time.Date(2026, 10, 7, 16, 44, 23, 0, time.UTC)
	ddpReplies = &ddpLimiter{last: map[string]time.Time{}}
	ddpNow = func() time.Time { return now }
	t.Cleanup(func() { ddpReplies, ddpNow = prevLimiter, prevNow })
	return &now
}

func TestHandleDDPSearchGetsStandby(t *testing.T) {
	withDDPState(t)
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()

	require.NoError(t, HandleDDP(context.Background(), src, dst, ddpCapturedSearch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "ddp", h.produced[0].handler)
	require.Equal(t, ddpCapturedSearch, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	want := ddp.BuildSearchResponse(ddp.ConsoleFor([]byte("198.51.100.1"), "00030010"))
	require.Equal(t, [][]byte{want}, h.replies)
	require.True(t, strings.HasPrefix(string(want), "HTTP/1.1 620 Server Standby\n"))
	require.Contains(t, string(want), "host-type:PS5\n")

	events, ok := h.produced[0].decoded.([]parsedDDP)
	require.True(t, ok)
	require.Equal(t, []parsedDDP{
		{Direction: "read", Command: "SRCH", Version: "00030010", Payload: ddpCapturedSearch},
		{Direction: "write", Command: "SRCH", Version: "00030010", HostType: "PS5", Status: "620", Payload: want},
	}, events)
}

func TestHandleDDPSearchCRLFPS4(t *testing.T) {
	withDDPState(t)
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()
	payload := []byte("SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:00020020\r\n")

	require.NoError(t, HandleDDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.Contains(t, string(h.replies[0]), "host-type:PS4\n")
	events := h.produced[0].decoded.([]parsedDDP)
	require.Len(t, events, 2)
	require.Equal(t, "00020020", events[1].Version)
	require.Equal(t, "PS4", events[1].HostType)
}

func TestHandleDDPWakeupNoReplyNoCredential(t *testing.T) {
	withDDPState(t)
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()
	payload := []byte("WAKEUP * HTTP/1.1\nclient-type:vr\nauth-type:R\nuser-credential:31337\ndevice-discovery-protocol-version:00020020\n")

	require.NoError(t, HandleDDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedDDP)
	require.Equal(t, []parsedDDP{{
		Direction:             "read",
		Command:               "WAKEUP",
		Version:               "00020020",
		ClientType:            "vr",
		UserCredentialPresent: true,
		Payload:               payload,
	}}, events)
}

func TestHandleDDPRateLimitsReplies(t *testing.T) {
	now := withDDPState(t)
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()

	for range 3 {
		require.NoError(t, HandleDDP(context.Background(), src, dst, ddpCapturedSearch, connection.Metadata{}, testLogger{}, h))
	}
	require.Len(t, h.produced, 3)
	require.Len(t, h.replies, 1)
	require.Len(t, h.produced[1].decoded.([]parsedDDP), 1)

	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.21"), Port: 5855}
	require.NoError(t, HandleDDP(context.Background(), other, dst, ddpCapturedSearch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 2)

	*now = now.Add(ddpReplyInterval)
	require.NoError(t, HandleDDP(context.Background(), src, dst, ddpCapturedSearch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 3)
}

func TestHandleDDPMalformed(t *testing.T) {
	src, dst := ddpAddrs()
	for name, payload := range map[string][]byte{
		"empty":       nil,
		"garbage":     {0x00, 0x01, 0xff},
		"no line end": []byte("SRCH * HTTP/1.1"),
	} {
		t.Run(name, func(t *testing.T) {
			withDDPState(t)
			h := &recordingHoneypot{}
			require.NoError(t, HandleDDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
			require.Len(t, h.produced, 1)
			require.Equal(t, "ddp", h.produced[0].handler)
			require.Empty(t, h.replies)
			events := h.produced[0].decoded.([]parsedDDP)
			require.Len(t, events, 1)
			require.Equal(t, "UNKNOWN", events[0].Command)
			require.Equal(t, len(payload), len(events[0].Payload))
		})
	}
}

func TestHandleDDPCapsOversizedPayload(t *testing.T) {
	withDDPState(t)
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()
	payload := append(append([]byte(nil), ddpCapturedSearch...), []byte(strings.Repeat("x", 2000))...)

	require.NoError(t, HandleDDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedDDP)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxDDPPayload)
	require.Equal(t, "SRCH", events[0].Command)
}

func TestHandleUDPReroutesDDP(t *testing.T) {
	withDDPState(t)
	h := &recordingHoneypot{}
	src, _ := ddpAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 40000}

	require.NoError(t, HandleUDP(context.Background(), src, dst, ddpCapturedSearch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "ddp", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPDoesNotRerouteSSDP(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ddpAddrs()

	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n"), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
}
