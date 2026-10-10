package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/hiflying"
	"github.com/stretchr/testify/require"
)

// Captured discovery probe (Ochi event b9cc7af5-7cbc-43d4-b11f-4b98458f72de).
var hiflyingRead1 = []byte{
	0x48, 0x46, 0x2d, 0x41, 0x31, 0x31, 0x41, 0x53, 0x53, 0x49, 0x53, 0x54, 0x48, 0x52, 0x45, 0x41,
	0x44,
}

func hiflyingAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 21154},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 48899}
}

func withHiFlyingState(t *testing.T) *time.Time {
	t.Helper()
	prevState, prevNow := hiflyingState, hiflyingNow
	now := time.Date(2026, 10, 10, 18, 40, 35, 0, time.UTC)
	hiflyingState = &hiflyingSessions{m: map[string]*hiflyingSession{}}
	hiflyingNow = func() time.Time { return now }
	t.Cleanup(func() { hiflyingState, hiflyingNow = prevState, prevNow })
	return &now
}

func sendHiFlying(t *testing.T, h *recordingHoneypot, src *net.UDPAddr, data string) []parsedHiFlying {
	t.Helper()
	_, dst := hiflyingAddrs()
	n := len(h.produced)
	require.NoError(t, HandleHiFlying(context.Background(), src, dst, []byte(data), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, n+1)
	require.Equal(t, "hiflying", h.produced[n].handler)
	require.Equal(t, connection.EndHandlerClose, h.produced[n].endReason)
	return h.produced[n].decoded.([]parsedHiFlying)
}

func TestHandleHiFlyingDiscovery(t *testing.T) {
	withHiFlyingState(t)
	h := &recordingHoneypot{}
	src, _ := hiflyingAddrs()

	events := sendHiFlying(t, h, src, string(hiflyingRead1))
	require.Equal(t, hiflyingRead1, h.produced[0].payload)
	want := hiflying.BuildDiscoveryReply(hiflying.ModuleFor([]byte("198.51.100.1")))
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, []parsedHiFlying{
		{Direction: "read", Command: "DISCOVER", Payload: hiflyingRead1},
		{Direction: "write", Command: "DISCOVER", Status: "DISCOVER_REPLY", Payload: want},
	}, events)
}

func TestHandleHiFlyingCommandSession(t *testing.T) {
	withHiFlyingState(t)
	h := &recordingHoneypot{}
	src, _ := hiflyingAddrs()
	mod := hiflying.ModuleFor([]byte("198.51.100.1"))

	// AT before discovery and before "+ok" is ignored, as on a module.
	require.Equal(t, []parsedHiFlying{{Direction: "read", Command: "AT+VER", Payload: []byte("AT+VER\r")}}, sendHiFlying(t, h, src, "AT+VER\r"))
	sendHiFlying(t, h, src, string(hiflyingRead1))
	require.Len(t, sendHiFlying(t, h, src, "AT+VER\r"), 1)

	require.Equal(t, []parsedHiFlying{{Direction: "read", Command: "ENTER_AT", Payload: []byte("+ok")}}, sendHiFlying(t, h, src, "+ok"))
	require.Len(t, h.replies, 1)

	require.Equal(t, []parsedHiFlying{
		{Direction: "read", Command: "AT+VER", Payload: []byte("AT+VER\r")},
		{Direction: "write", Command: "AT+VER", Status: "OK", Payload: []byte("+ok=1.0.06a-14 (2015-09-08 10:20 1M)\r\n\r\n")},
	}, sendHiFlying(t, h, src, "AT+VER\r"))
	require.Equal(t, []parsedHiFlying{
		{Direction: "read", Command: "AT+WSKEY", Payload: []byte("AT+WSKEY\r")},
		{Direction: "write", Command: "AT+WSKEY", Status: "OK", Payload: []byte("+ok=WPA2PSK,AES," + mod.Key + "\r\n\r\n")},
	}, sendHiFlying(t, h, src, "AT+WSKEY\r"))
	require.Equal(t, []parsedHiFlying{
		{Direction: "read", Command: "AT+FOO", Payload: []byte("AT+FOO\r")},
		{Direction: "write", Command: "AT+FOO", Status: "ERR", Payload: []byte("+ERR=-2\r\n\r\n")},
	}, sendHiFlying(t, h, src, "AT+FOO\r"))
	require.Equal(t, []parsedHiFlying{
		{Direction: "read", Command: "AT+UPURL", Path: "http://example.invalid/fw.bin", Payload: []byte("AT+UPURL=http://example.invalid/fw.bin\r")},
		{Direction: "write", Command: "AT+UPURL", Status: "OK", Payload: []byte("+ok\r\n\r\n")},
	}, sendHiFlying(t, h, src, "AT+UPURL=http://example.invalid/fw.bin\r"))

	// AT+Q leaves command mode.
	require.Len(t, sendHiFlying(t, h, src, "AT+Q\r"), 2)
	require.Len(t, sendHiFlying(t, h, src, "AT+VER\r"), 1)
}

func TestHandleHiFlyingMasksSecrets(t *testing.T) {
	withHiFlyingState(t)
	h := &recordingHoneypot{}
	src, _ := hiflyingAddrs()
	sendHiFlying(t, h, src, string(hiflyingRead1))
	sendHiFlying(t, h, src, "+ok")

	events := sendHiFlying(t, h, src, "AT+WSKEY=WPA2PSK,AES,hunter22\r")
	require.Equal(t, parsedHiFlying{Direction: "read", Command: "AT+WSKEY", Path: "WPA2PSK,AES,***", Payload: []byte("AT+WSKEY=WPA2PSK,AES,***\r")}, events[0])
	require.Equal(t, []byte("AT+WSKEY=WPA2PSK,AES,***\r"), h.produced[len(h.produced)-1].payload)
	require.NotContains(t, string(h.produced[len(h.produced)-1].payload), "hunter22")
}

func TestHandleHiFlyingUnknown(t *testing.T) {
	withHiFlyingState(t)
	src, _ := hiflyingAddrs()
	for name, in := range map[string]string{
		"empty":          "",
		"other password": "WIFIKIT-214028-READ",
		"garbage":        "\x00\x01\x02\xff",
	} {
		t.Run(name, func(t *testing.T) {
			h := &recordingHoneypot{}
			require.Equal(t, []parsedHiFlying{{Direction: "read", Command: "UNKNOWN", Payload: []byte(in)}}, sendHiFlying(t, h, src, in))
			require.Empty(t, h.replies)
		})
	}
}

func TestHandleHiFlyingTruncates(t *testing.T) {
	withHiFlyingState(t)
	h := &recordingHoneypot{}
	src, _ := hiflyingAddrs()
	big := make([]byte, maxHiFlyingPayload+10)
	events := sendHiFlying(t, h, src, string(big))
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxHiFlyingPayload)
}

func TestHandleHiFlyingRateLimits(t *testing.T) {
	now := withHiFlyingState(t)
	h := &recordingHoneypot{}
	src, _ := hiflyingAddrs()
	for range 3 {
		sendHiFlying(t, h, src, string(hiflyingRead1))
	}
	require.Len(t, h.replies, 1)

	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.21"), Port: 21154}
	sendHiFlying(t, h, other, string(hiflyingRead1))
	require.Len(t, h.replies, 2)

	*now = now.Add(hiflyingDiscoveryInterval)
	sendHiFlying(t, h, src, string(hiflyingRead1))
	require.Len(t, h.replies, 3)

	// AT replies are capped per source per interval.
	sendHiFlying(t, h, src, "+ok")
	for range hiflyingMaxATReplies + 5 {
		sendHiFlying(t, h, src, "AT+VER\r")
	}
	require.Len(t, h.replies, 3+hiflyingMaxATReplies)
	*now = now.Add(hiflyingDiscoveryInterval)
	sendHiFlying(t, h, src, "AT+VER\r")
	require.Len(t, h.replies, 4+hiflyingMaxATReplies)

	// The session expires after the TTL; AT is ignored again.
	*now = now.Add(hiflyingSessionTTL)
	require.Len(t, sendHiFlying(t, h, src, "AT+VER\r"), 1)
}

func TestHandleUDPReroutesHiFlying(t *testing.T) {
	withHiFlyingState(t)
	src, _ := hiflyingAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 40000}

	// A command from an unknown source stays with the catch-all.
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("+ok"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)

	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, hiflyingRead1, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "hiflying", h.produced[0].handler)
	require.Len(t, h.replies, 1)

	// Follow-ups from that source are rerouted too.
	for _, in := range []string{"+ok", "AT+MID\r"} {
		require.NoError(t, HandleUDP(context.Background(), src, dst, []byte(in), connection.Metadata{}, testLogger{}, h))
	}
	require.Equal(t, "hiflying", h.produced[2].handler)
	require.Len(t, h.replies, 2)

	// Unrelated traffic from that source still goes to the catch-all.
	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("hello"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}
