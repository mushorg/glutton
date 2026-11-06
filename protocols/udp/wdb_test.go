package udp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/mushorg/glutton/protocols/udp/wdb"
	"github.com/stretchr/testify/require"
)

// Censys WDB_TARGET_CONNECT to udp/17185 (captured 2026-11-06, 66.132.224.22).
var wdbCensysConnect = []byte{
	0x1a, 0x09, 0xfa, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x55, 0x55, 0x55, 0x55,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x55, 0x12, 0x00, 0x00, 0x00, 0x3c,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func wdbAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 40000},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 17185}
}

func TestHandleWDBConnect(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := wdbAddrs()

	require.NoError(t, HandleWDB(context.Background(), src, dst, wdbCensysConnect, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "wdb", h.produced[0].handler)
	require.Equal(t, wdbCensysConnect, h.produced[0].payload)
	require.Len(t, h.replies, 1)

	reply := h.replies[0]
	require.Equal(t, uint32(0x1a09faba), binary.BigEndian.Uint32(reply), "echoed XID")
	c, err := oncrpc.Parse(wdbCensysConnect)
	require.NoError(t, err)
	want, _ := wdb.Reply(c, wdb.DefaultTarget)
	require.Equal(t, want, reply)
	require.Equal(t, []parsedWDB{
		{Direction: "read", Command: "WDB_TARGET_CONNECT", XID: 0x1a09faba, Program: wdb.Program, Version: 1, Procedure: 1, Auth: "AUTH_NONE", Seq: 1, Payload: wdbCensysConnect},
		{Direction: "write", Command: "WDB_TARGET_CONNECT", XID: 0x1a09faba, Status: "SUCCESS", Payload: reply},
	}, h.produced[0].decoded)
}

func TestHandleWDBMemRead(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := wdbAddrs()
	call := append([]byte{}, wdbCensysConnect...)
	binary.BigEndian.PutUint32(call[20:], 10) // WDB_MEM_READ

	require.NoError(t, HandleWDB(context.Background(), src, dst, call, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	frames := h.produced[0].decoded.([]parsedWDB)
	require.Len(t, frames, 2)
	require.Equal(t, "WDB_MEM_READ", frames[0].Command)
	require.Equal(t, "PROC_UNAVAIL", frames[1].Status)
}

func TestHandleWDBNoReply(t *testing.T) {
	src, dst := wdbAddrs()
	for _, tc := range []struct {
		name string
		data []byte
		cmd  string
	}{
		{"garbage", []byte("\n"), "UNKNOWN"},
		{"reply message", []byte{0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0}, "REPLY"},
		{"truncated call", wdbCensysConnect[:24], "WDB_TARGET_CONNECT"},
		{"oversize", append(append([]byte{}, wdbCensysConnect...), bytes.Repeat([]byte{0}, 2000)...), "WDB_TARGET_CONNECT"},
	} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleWDB(context.Background(), src, dst, tc.data, connection.Metadata{}, testLogger{}, h), tc.name)
		require.Len(t, h.produced, 1, tc.name)
		require.Empty(t, h.replies, tc.name)
		frames := h.produced[0].decoded.([]parsedWDB)
		require.Len(t, frames, 1, tc.name)
		require.Equal(t, tc.cmd, frames[0].Command, tc.name)
		require.Equal(t, len(tc.data) > maxWDBPayload, frames[0].Truncated, tc.name)
		require.LessOrEqual(t, len(frames[0].Payload), maxWDBPayload, tc.name)
	}
}
