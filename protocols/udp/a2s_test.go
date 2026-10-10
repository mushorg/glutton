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

// Captured A2S_INFO probe (Ochi event 30663010-330d-4591-a029-ed39571b919d).
func a2sCapturedInfo(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("ffffffff54536f7572636520456e67696e6520517565727900")
	require.NoError(t, err)
	return b
}

func withA2SRand(t *testing.T, b []byte) {
	t.Helper()
	prev := a2sRand
	a2sRand = bytes.NewReader(b)
	t.Cleanup(func() { a2sRand = prev })
}

func a2sAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 52243},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 27015}
}

func TestHandleA2SInfoGetsChallenge(t *testing.T) {
	withA2SRand(t, []byte{0xde, 0xad, 0xbe, 0xef})
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload := a2sCapturedInfo(t)

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "a2s", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)

	want := []byte{0xff, 0xff, 0xff, 0xff, 0x41, 0xde, 0xad, 0xbe, 0xef}
	require.Equal(t, [][]byte{want}, h.replies)
	require.LessOrEqual(t, len(h.replies[0]), len(payload))

	events, ok := h.produced[0].decoded.([]parsedA2S)
	require.True(t, ok)
	require.Equal(t, []parsedA2S{
		{Direction: "read", Command: "A2S_INFO", RequestType: 0x54, Query: "Source Engine Query", Payload: payload},
		{Direction: "write", Command: "S2C_CHALLENGE", RequestType: 0x41, Challenge: "deadbeef", Status: "S2C_CHALLENGE", Payload: want},
	}, events)
}

// Unterminated A2S_INFO probe (Ochi event 04a9a553-2ae9-4615-8167-e930548cc021).
func TestHandleA2SInfoWithoutNULGetsChallenge(t *testing.T) {
	withA2SRand(t, []byte{0xde, 0xad, 0xbe, 0xef})
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload, err := hex.DecodeString("ffffffff54536f7572636520456e67696e65205175657279")
	require.NoError(t, err)

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	want := []byte{0xff, 0xff, 0xff, 0xff, 0x41, 0xde, 0xad, 0xbe, 0xef}
	require.Equal(t, [][]byte{want}, h.replies)
	events := h.produced[0].decoded.([]parsedA2S)
	require.Equal(t, []parsedA2S{
		{Direction: "read", Command: "A2S_INFO", RequestType: 0x54, Query: "Source Engine Query", Payload: payload},
		{Direction: "write", Command: "S2C_CHALLENGE", RequestType: 0x41, Challenge: "deadbeef", Status: "S2C_CHALLENGE", Payload: want},
	}, events)
}

func TestHandleA2SInfoWithChallengeNoReply(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload := append(a2sCapturedInfo(t), 0xde, 0xad, 0xbe, 0xef)

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedA2S)
	require.Equal(t, []parsedA2S{
		{Direction: "read", Command: "A2S_INFO", RequestType: 0x54, Query: "Source Engine Query", Challenge: "deadbeef", Payload: payload},
	}, events)
}

func TestHandleA2SPlayerChallengeRequest(t *testing.T) {
	withA2SRand(t, []byte{1, 2, 3, 4})
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0x55, 0xff, 0xff, 0xff, 0xff}

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, [][]byte{{0xff, 0xff, 0xff, 0xff, 0x41, 1, 2, 3, 4}}, h.replies)
	events := h.produced[0].decoded.([]parsedA2S)
	require.Len(t, events, 2)
	require.Equal(t, "A2S_PLAYER", events[0].Command)
	require.Equal(t, "ffffffff", events[0].Challenge)
	require.Equal(t, "01020304", events[1].Challenge)
}

func TestHandleA2SGetChallengeNoAmplification(t *testing.T) {
	withA2SRand(t, []byte{1, 2, 3, 4})
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0x57}

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedA2S)
	require.Equal(t, []parsedA2S{{Direction: "read", Command: "A2S_SERVERQUERY_GETCHALLENGE", RequestType: 0x57, Payload: payload}}, events)
}

func TestHandleA2SMalformed(t *testing.T) {
	src, dst := a2sAddrs()
	for name, payload := range map[string][]byte{
		"short":     {0xff, 0xff},
		"unknown":   {0xff, 0xff, 0xff, 0xff, 0x7a},
		"truncated": {0xff, 0xff, 0xff, 0xff, 0x55, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			h := &recordingHoneypot{}
			require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
			require.Len(t, h.produced, 1)
			require.Equal(t, "a2s", h.produced[0].handler)
			require.Empty(t, h.replies)
			events := h.produced[0].decoded.([]parsedA2S)
			require.Len(t, events, 1)
			require.Equal(t, payload, events[0].Payload)
		})
	}
}

func TestHandleA2SEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	require.NoError(t, HandleA2S(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
}

func TestHandleA2SCapsOversizedPayload(t *testing.T) {
	withA2SRand(t, []byte{1, 2, 3, 4})
	h := &recordingHoneypot{}
	src, dst := a2sAddrs()
	payload := append(a2sCapturedInfo(t), make([]byte, 2000)...)

	require.NoError(t, HandleA2S(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedA2S)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxA2SPayload)
}

func TestHandleUDPReroutesA2S(t *testing.T) {
	withA2SRand(t, []byte{1, 2, 3, 4})
	h := &recordingHoneypot{}
	src, _ := a2sAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 27016}

	require.NoError(t, HandleUDP(context.Background(), src, dst, a2sCapturedInfo(t), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "a2s", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}
