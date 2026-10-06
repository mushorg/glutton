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

// read frame 1 of Ochi event ddf44883-a01b-495a-90d8-a200df969d38 (SIPVicious INVITE to udp/65476)
var sipviciousInviteRead1 = []byte("INVITE sip:100@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 172.110.223.188:5069;branch=z9hG4bK-829846850;rport\r\nContent-Length: 0\r\nFrom: \"sipvicious\"<sip:100@1.1.1.1>;tag=613361636136646466666334013237343639353932\r\nAccept: application/sdp\r\nUser-Agent: friendly-scanner\r\nTo: \"sipvicious\"<sip:100@1.1.1.1>\r\nContact: sip:100@172.110.223.188:5069\r\nCSeq: 1 INVITE\r\nCall-ID: 991852993801236740384404\r\nMax-Forwards: 70\r\n\r\n")

func TestHandleUDPPeeksSIP(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("172.110.223.188"), Port: 5069}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 65476}

	err := HandleUDP(context.Background(), src, dst, sipviciousInviteRead1, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.Equal(t, sipviciousInviteRead1, h.produced[0].payload)
	require.Len(t, h.replies, 3)

	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 4)
	require.Equal(t, parsedSIP{
		Direction: "read",
		Command:   "INVITE",
		Path:      "sip:100@1.2.3.4",
		From:      "sip:100@1.1.1.1",
		To:        "sip:100@1.1.1.1",
		CallID:    "991852993801236740384404",
		UserAgent: "friendly-scanner",
		Payload:   sipviciousInviteRead1,
	}, events[0])
	for i, status := range []string{"100", "180", "200"} {
		require.Equal(t, "write", events[i+1].Direction)
		require.Equal(t, status, events[i+1].Status)
		require.Equal(t, h.replies[i], events[i+1].Payload)
	}
}

func TestHandleUDPDoesNotPeekHTTPAsSIP(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 65476}
	payload := []byte("GET / HTTP/1.1\r\nHost: 198.51.100.1\r\n\r\n")

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Empty(t, h.replies)
}
