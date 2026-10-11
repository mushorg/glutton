package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Captured RIPv1 whole-table request from 207.90.244.27
// (Ochi event d52ce31e-9b16-40a0-94fd-55bbed727932).
var ripRead1 = []byte{
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

func ripAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("207.90.244.27"), Port: 12902},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 520}
}

func TestHandleRIPWholeTable(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ripAddrs()

	require.NoError(t, HandleRIP(context.Background(), src, dst, ripRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "rip", h.produced[0].handler)
	require.Equal(t, ripRead1, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	want := []byte{
		2, 1, 0, 0,
		0, 2, 0, 0, 192, 168, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}
	require.Equal(t, [][]byte{want}, h.replies)
	require.Len(t, want, len(ripRead1))
	require.Equal(t, []parsedRIP{
		{Direction: "read", Command: "request", Version: 1, WholeTable: true,
			Entries: []ripEntry{{AFI: 0, Address: "0.0.0.0", Metric: 16}}, Payload: ripRead1},
		{Direction: "write", Command: "response", Version: 1,
			Entries: []ripEntry{{AFI: 2, Address: "192.168.79.0", Metric: 1}}, Status: "response", Payload: want},
	}, h.produced[0].decoded)
}

func TestHandleRIPv2SimpleAuth(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ripAddrs()
	req := []byte{1, 2, 0, 0, 0xff, 0xff, 0, 2}
	req = append(req, []byte("cisco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")...)
	req = append(req, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16)

	require.NoError(t, HandleRIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedRIP)
	require.Len(t, events, 2)
	require.Equal(t, parsedRIP{
		Direction: "read", Command: "request", Version: 2, WholeTable: true,
		Entries:  []ripEntry{{AFI: 0, Address: "0.0.0.0", Mask: "0.0.0.0", NextHop: "0.0.0.0", Metric: 16}},
		AuthType: "simple", Password: "cisco", Payload: req,
	}, events[0])
	require.Equal(t, []ripEntry{{AFI: 2, Address: "192.168.79.0", Mask: "255.255.255.0", NextHop: "0.0.0.0", Metric: 1}}, events[1].Entries)
	require.Len(t, h.replies, 1)
	require.Less(t, len(h.replies[0]), len(req))
}

func TestHandleRIPResponseIsRecordedOnly(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ripAddrs()
	// Route injection: a RIPv2 Response advertising a default route.
	resp := []byte{2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 66, 0, 0, 0, 1}

	require.NoError(t, HandleRIP(context.Background(), src, dst, resp, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedRIP{{
		Direction: "read", Command: "response", Version: 2,
		Entries: []ripEntry{{AFI: 2, Address: "0.0.0.0", Mask: "0.0.0.0", NextHop: "203.0.113.66", Metric: 1}},
		Payload: resp,
	}}, h.produced[0].decoded)
}

func TestHandleRIPMalformed(t *testing.T) {
	src, dst := ripAddrs()
	for name, data := range map[string][]byte{
		"short":       {1},
		"partial rte": ripRead1[:20],
		"no entries":  ripRead1[:4],
		"bad version": append([]byte{1, 7, 0, 0}, ripRead1[4:]...),
	} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleRIP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h), name)
		require.Len(t, h.produced, 1, name)
		require.Empty(t, h.replies, name)
		events := h.produced[0].decoded.([]parsedRIP)
		require.Len(t, events, 1, name)
		require.Equal(t, data, events[0].Payload, name)
	}
}

func TestHandleRIPCapsOversizedPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ripAddrs()
	data := append([]byte{1, 1, 0, 0}, make([]byte, 2000)...)

	require.NoError(t, HandleRIP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedRIP)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxRIPPayload)
	require.Empty(t, h.replies)
}

func TestHandleUDPPeeksRIP(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("207.90.244.27"), Port: 12902}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5200}

	require.NoError(t, HandleUDP(context.Background(), src, dst, ripRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "rip", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPDoesNotPeekNonRIP(t *testing.T) {
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 68}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 520}
	// DHCP-like: op 1, htype 1, hlen 6 — byte 2 is not zero.
	data := append([]byte{1, 1, 6, 0}, ripRead1[4:]...)

	require.NoError(t, HandleUDP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Empty(t, h.replies)
}
