package udp

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/guard"
	"github.com/mushorg/glutton/protocols/udp/tftp"
	"github.com/stretchr/testify/require"
)

// Captured RRQ from 122.8.156.185
// (Ochi event 59795bc9-f579-42b8-890d-8dab9b753ff3).
var tftpRead1 = []byte{
	0x00, 0x01, 0x70, 0x6f, 0x6c, 0x79, 0x63, 0x6f, 0x6d, 0x34, 0x33, 0x30, 0x00, 0x6f, 0x63, 0x74,
	0x65, 0x74, 0x00,
}

// useTFTPGuard swaps in a fresh guard for the test so budgets never leak
// between tests that share a source IP.
func useTFTPGuard(t *testing.T, cfg guard.Config) {
	t.Helper()
	old := tftpGuard
	tftpGuard = guard.New(cfg)
	t.Cleanup(func() { tftpGuard = old })
}

func tftpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("122.8.156.185"), Port: 55095},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 69}
}

func TestHandleTFTPRRQ(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()

	require.NoError(t, HandleTFTP(context.Background(), src, dst, tftpRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "tftp", h.produced[0].handler)
	require.Equal(t, tftpRead1, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	// The full ERROR packet is exactly as large as the 19-byte request.
	want := []byte("\x00\x05\x00\x01File not found\x00")
	require.Len(t, want, len(tftpRead1))
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, []parsedTFTP{
		{Direction: "read", Command: "RRQ", Path: "polycom430", Mode: "octet", Payload: tftpRead1},
		{Direction: "write", Command: "ERROR", Status: "file_not_found", Payload: want},
	}, h.produced[0].decoded)
}

// Captured infrawatch RRQ with tsize and blksize options
// (Ochi event a8422eb1-bd48-4720-94e3-f4976a2e5782).
var tftpInfrawatch = []byte("\x00\x01infrawatch-78acbad23553d4cd2db8b7fa4c34d612.probe\x00octet\x00tsize\x000\x00blksize\x0016\x00")

func TestHandleTFTPRRQOptionsGetOACK(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()

	require.NoError(t, HandleTFTP(context.Background(), src, dst, tftpInfrawatch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "tftp", h.produced[0].handler)
	require.Equal(t, tftpInfrawatch, h.produced[0].payload)

	acked := []tftp.Option{
		{Name: "tsize", Value: strconv.Itoa(tftp.SizeFor("infrawatch-78acbad23553d4cd2db8b7fa4c34d612.probe"))},
		{Name: "blksize", Value: "16"},
	}
	want := tftp.OACKPacket(acked)
	require.Equal(t, [][]byte{want}, h.replies)
	require.Less(t, len(want), len(tftpInfrawatch))
	require.Equal(t, []parsedTFTP{
		{
			Direction: "read", Command: "RRQ", Path: "infrawatch-78acbad23553d4cd2db8b7fa4c34d612.probe", Mode: "octet",
			Options: []tftp.Option{{Name: "tsize", Value: "0"}, {Name: "blksize", Value: "16"}}, Payload: tftpInfrawatch,
		},
		{Direction: "write", Command: "OACK", Status: "oack", Options: acked, Payload: want},
	}, h.produced[0].decoded)
}

func TestHandleTFTPUnrecognisedOptionsGetError(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	req := []byte("\x00\x01polycom430\x00octet\x00windowsize\x004\x00")

	require.NoError(t, HandleTFTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedTFTP)
	require.Equal(t, "ERROR", events[1].Command)
	require.Equal(t, "file_not_found", events[1].Status)
	require.LessOrEqual(t, len(h.replies[0]), len(req))
}

func TestHandleTFTPWRQOptionsStillAccessViolation(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	req := []byte("\x00\x02a.cfg\x00octet\x00blksize\x001468\x00")

	require.NoError(t, HandleTFTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedTFTP)
	require.Equal(t, "access_violation", events[1].Status)
}

func TestHandleTFTPShortRequestTrimsReply(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	req := []byte("\x00\x01a\x00octet\x00")

	require.NoError(t, HandleTFTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(req))
}

func TestHandleTFTPWRQ(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	req := []byte("\x00\x02../../etc/passwd\x00octet\x00tsize\x00512\x00")

	require.NoError(t, HandleTFTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedTFTP)
	require.Len(t, events, 2)
	require.Equal(t, "WRQ", events[0].Command)
	require.Equal(t, "../../etc/passwd", events[0].Path)
	require.Equal(t, []tftp.Option{{Name: "tsize", Value: "512"}}, events[0].Options)
	require.Equal(t, "access_violation", events[1].Status)
	require.Equal(t, []byte("\x00\x05\x00\x02Access violation\x00"), h.replies[0])
	require.LessOrEqual(t, len(h.replies[0]), len(req))
}

func TestHandleTFTPMalformed(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	bad := []byte{0x00, 0x01, 0x61}

	require.NoError(t, HandleTFTP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedTFTP{{Direction: "read", Command: "unknown", Payload: bad}}, h.produced[0].decoded)
}

func TestHandleTFTPRoutedFromCatchAll(t *testing.T) {
	useTFTPGuard(t, tftpGuardConfig())
	src, dst := tftpAddrs()
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, tftpRead1, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "tftp", h.produced[0].handler)

	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("\x00\x01hello"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}

func TestHandleTFTPBurstIsLimitedPerSource(t *testing.T) {
	cfg := tftpGuardConfig()
	cfg.SourceRequestRate = 1
	useTFTPGuard(t, cfg)
	src, dst := tftpAddrs()
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}

	h := &recordingHoneypot{}
	for range 20 {
		require.NoError(t, HandleTFTP(context.Background(), src, dst, tftpInfrawatch, connection.Metadata{}, testLogger{}, h))
	}
	require.Len(t, h.produced, 20, "every request is still recorded")
	require.Len(t, h.replies, int(cfg.SourceRequestBurst), "replies stop at the per-source burst")

	// A refused reply stays in the event as a write frame, like udp_reply_limit.
	last := h.produced[19].decoded.([]parsedTFTP)
	require.Len(t, last, 2)
	require.Equal(t, "OACK", last[1].Command)

	// Another source has its own budget.
	require.NoError(t, HandleTFTP(context.Background(), other, dst, tftpInfrawatch, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, int(cfg.SourceRequestBurst)+1)
}

func TestHandleTFTPGlobalBudgetCoversManySources(t *testing.T) {
	cfg := tftpGuardConfig()
	cfg.GlobalRequestRate = 1
	cfg.GlobalRequestBurst = 3
	useTFTPGuard(t, cfg)
	_, dst := tftpAddrs()

	h := &recordingHoneypot{}
	for i := range 10 {
		src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(10+i)), Port: 4000}
		require.NoError(t, HandleTFTP(context.Background(), src, dst, tftpInfrawatch, connection.Metadata{}, testLogger{}, h))
	}
	require.Len(t, h.produced, 10)
	require.Len(t, h.replies, 3)
}

func TestTFTPGuardBurstFitsLargestReply(t *testing.T) {
	// A reply is at most as large as a request, and requests are stored up to
	// maxTFTPPayload; the byte burst must allow one such reply.
	require.GreaterOrEqual(t, tftpGuardConfig().SourceBurst, maxTFTPPayload)
}
