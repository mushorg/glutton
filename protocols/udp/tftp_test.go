package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/tftp"
	"github.com/stretchr/testify/require"
)

// Captured RRQ from 122.8.156.185
// (Ochi event 59795bc9-f579-42b8-890d-8dab9b753ff3).
var tftpRead1 = []byte{
	0x00, 0x01, 0x70, 0x6f, 0x6c, 0x79, 0x63, 0x6f, 0x6d, 0x34, 0x33, 0x30, 0x00, 0x6f, 0x63, 0x74,
	0x65, 0x74, 0x00,
}

func tftpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("122.8.156.185"), Port: 55095},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 69}
}

func TestHandleTFTPRRQ(t *testing.T) {
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

func TestHandleTFTPShortRequestTrimsReply(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	req := []byte("\x00\x01a\x00octet\x00")

	require.NoError(t, HandleTFTP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(req))
}

func TestHandleTFTPWRQ(t *testing.T) {
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
	h := &recordingHoneypot{}
	src, dst := tftpAddrs()
	bad := []byte{0x00, 0x01, 0x61}

	require.NoError(t, HandleTFTP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedTFTP{{Direction: "read", Command: "unknown", Payload: bad}}, h.produced[0].decoded)
}

func TestHandleTFTPRoutedFromCatchAll(t *testing.T) {
	src, dst := tftpAddrs()
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, tftpRead1, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "tftp", h.produced[0].handler)

	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("\x00\x01hello"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}
