package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/knx"
	"github.com/stretchr/testify/require"
)

// Captured DESCRIPTION_REQUEST (Ochi event 25167000-a41c-4107-ac35-342898a51e57).
var knxCapturedDescription = []byte{0x06, 0x10, 0x02, 0x03, 0x00, 0x0e, 0x08, 0x01, 0xcf, 0x5a, 0xf4, 0x03, 0x0e, 0x58}

func knxAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 3672},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3671}
}

func withKNXState(t *testing.T) *time.Time {
	t.Helper()
	prevLimiter, prevNow := knxReplies, knxNow
	now := time.Date(2026, 10, 7, 16, 44, 23, 0, time.UTC)
	knxReplies = &knxLimiter{last: map[string]time.Time{}}
	knxNow = func() time.Time { return now }
	t.Cleanup(func() { knxReplies, knxNow = prevLimiter, prevNow })
	return &now
}

func TestHandleKNXDescription(t *testing.T) {
	withKNXState(t)
	h := &recordingHoneypot{}
	src, dst := knxAddrs()

	require.NoError(t, HandleKNX(context.Background(), src, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "knx", h.produced[0].handler)
	require.Equal(t, knxCapturedDescription, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	want := knx.BuildDescriptionResponse(knx.DeviceFor([]byte("198.51.100.1")))
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, []parsedKNX{
		{Direction: "read", Command: "DESCRIPTION_REQUEST", ServiceType: "0x0203", HPAIIP: "207.90.244.3", HPAIPort: 3672, Payload: knxCapturedDescription},
		{Direction: "write", Command: "DESCRIPTION_REQUEST", ServiceType: "0x0204", Status: "DESCRIPTION_RESPONSE", Payload: want},
	}, h.produced[0].decoded)
}

func TestHandleKNXSearchAndConnect(t *testing.T) {
	withKNXState(t)
	src, dst := knxAddrs()

	h := &recordingHoneypot{}
	search := []byte{6, 0x10, 0x02, 0x01, 0, 14, 8, 1, 0, 0, 0, 0, 0, 0}
	require.NoError(t, HandleKNX(context.Background(), src, dst, search, connection.Metadata{}, testLogger{}, h))
	want := knx.BuildSearchResponse(knx.DeviceFor([]byte("198.51.100.1")), dst.IP, 3671)
	require.Equal(t, [][]byte{want}, h.replies)
	events := h.produced[0].decoded.([]parsedKNX)
	require.Equal(t, "SEARCH_RESPONSE", events[1].Status)
	require.Equal(t, "0x0202", events[1].ServiceType)

	h = &recordingHoneypot{}
	connect := []byte{6, 0x10, 0x02, 0x05, 0, 26, 8, 1, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 4, 4, 2, 0}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.21"), Port: 3672}
	require.NoError(t, HandleKNX(context.Background(), other, dst, connect, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, [][]byte{knx.BuildConnectError()}, h.replies)
	require.Equal(t, "E_NO_MORE_CONNECTIONS", h.produced[0].decoded.([]parsedKNX)[1].Status)
}

// addrHoneypot records the addresses ReplyUDP is called with.
type addrHoneypot struct {
	recordingHoneypot
	srcs, dsts []*net.UDPAddr
}

func (h *addrHoneypot) ReplyUDP(srcAddr, dstAddr *net.UDPAddr, payload []byte) error {
	h.srcs, h.dsts = append(h.srcs, srcAddr), append(h.dsts, dstAddr)
	return h.recordingHoneypot.ReplyUDP(srcAddr, dstAddr, payload)
}

func TestHandleKNXRepliesGoToSourceNotHPAI(t *testing.T) {
	withKNXState(t)
	h := &addrHoneypot{}
	src, dst := knxAddrs()
	require.NoError(t, HandleKNX(context.Background(), src, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	// ReplyUDP(srcAddr, dstAddr) answers srcAddr; the HPAI 207.90.244.3:3672 is never used.
	require.Equal(t, src, h.srcs[0])
	require.Equal(t, dst, h.dsts[0])
}

func TestHandleKNXRecordOnly(t *testing.T) {
	withKNXState(t)
	h := &recordingHoneypot{}
	src, dst := knxAddrs()
	disc := []byte{6, 0x10, 0x02, 0x09, 0, 16, 0x15, 0, 8, 1, 10, 0, 0, 1, 0x0e, 0x57}
	require.NoError(t, HandleKNX(context.Background(), src, dst, disc, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedKNX{
		{Direction: "read", Command: "DISCONNECT_REQUEST", ServiceType: "0x0209", HPAIIP: "10.0.0.1", HPAIPort: 3671, Payload: disc},
	}, h.produced[0].decoded)
}

func TestHandleKNXMalformed(t *testing.T) {
	src, dst := knxAddrs()
	mismatch := append([]byte(nil), knxCapturedDescription...)
	mismatch[5] = 0x20
	for name, tc := range map[string]struct {
		payload []byte
		service string
	}{
		"empty":           {[]byte{}, ""},
		"truncated":       {knxCapturedDescription[:4], ""},
		"length mismatch": {mismatch, "0x0203"},
		"bad magic":       {[]byte{0x07, 0x10, 0x02, 0x03, 0x00, 0x08, 0, 0}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			withKNXState(t)
			h := &recordingHoneypot{}
			require.NoError(t, HandleKNX(context.Background(), src, dst, tc.payload, connection.Metadata{}, testLogger{}, h))
			require.Len(t, h.produced, 1)
			require.Empty(t, h.replies)
			require.Equal(t, []parsedKNX{{Direction: "read", Command: "UNKNOWN", ServiceType: tc.service, Payload: tc.payload}}, h.produced[0].decoded)
		})
	}
}

func TestHandleKNXRateLimitsReplies(t *testing.T) {
	now := withKNXState(t)
	h := &recordingHoneypot{}
	src, dst := knxAddrs()
	for range 3 {
		require.NoError(t, HandleKNX(context.Background(), src, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	}
	require.Len(t, h.produced, 3)
	require.Len(t, h.replies, 1)
	require.Len(t, h.produced[1].decoded.([]parsedKNX), 1)

	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.21"), Port: 3672}
	require.NoError(t, HandleKNX(context.Background(), other, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 2)

	*now = now.Add(knxReplyInterval)
	require.NoError(t, HandleKNX(context.Background(), src, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 3)
}

func TestHandleUDPReroutesKNX(t *testing.T) {
	withKNXState(t)
	h := &recordingHoneypot{}
	src, _ := knxAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 40000}
	require.NoError(t, HandleUDP(context.Background(), src, dst, knxCapturedDescription, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "knx", h.produced[0].handler)
	require.Len(t, h.replies, 1)

	// Length mismatch stays with the catch-all.
	h = &recordingHoneypot{}
	bad := append([]byte(nil), knxCapturedDescription...)
	bad[5] = 0x20
	require.NoError(t, HandleUDP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}
