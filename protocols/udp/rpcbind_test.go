package udp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/stretchr/testify/require"
)

// The Shodan PMAPPROC_DUMP from Ochi event c6b98aad-61b0-4449-ac2c-88d5cdd4b111
// without its TCP record mark, as the same call arrives over UDP.
var rpcbindUDPDump = []byte{
	0xe8, 0x77, 0xbb, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func rpcbindWords(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return b
}

func rpcbindAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 816},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 111}
}

func TestHandleRPCBindUDPDump(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := rpcbindAddrs()

	require.NoError(t, HandleRPCBind(context.Background(), src, dst, rpcbindUDPDump, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "rpcbind", h.produced[0].handler)
	require.Equal(t, rpcbindUDPDump, h.produced[0].payload)
	require.Len(t, h.replies, 1)

	reply := h.replies[0]
	require.Equal(t, uint32(0xe877bb11), binary.BigEndian.Uint32(reply), "echoed XID, no record mark")
	want, _ := oncrpc.Reply(&oncrpc.Call{XID: 0xe877bb11, RPCVersion: 2, Program: 100000, Version: 2, Procedure: 4},
		oncrpc.Env{Mappings: oncrpc.Mappings([]byte("198.51.100.1"))})
	require.Equal(t, want, reply)
	require.Less(t, len(reply), 700)
	require.Equal(t, []parsedRPCBind{
		{Direction: "read", Command: "PMAPPROC_DUMP", XID: 0xe877bb11, Program: 100000, Version: 2, Procedure: 4, Auth: "AUTH_NONE", Payload: rpcbindUDPDump},
		{Direction: "write", Command: "PMAPPROC_DUMP", XID: 0xe877bb11, Status: "SUCCESS", Payload: reply},
	}, h.produced[0].decoded)
}

func TestHandleRPCBindUDPNoReply(t *testing.T) {
	src, dst := rpcbindAddrs()
	for _, tc := range []struct {
		name string
		data []byte
		cmd  string
	}{
		{"garbage", []byte("hello"), "UNKNOWN"},
		{"reply message", []byte{0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0}, "REPLY"},
		{"oversize", append(append([]byte{}, rpcbindUDPDump...), bytes.Repeat([]byte{0}, 2000)...), "PMAPPROC_DUMP"},
	} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleRPCBind(context.Background(), src, dst, tc.data, connection.Metadata{}, testLogger{}, h), tc.name)
		require.Len(t, h.produced, 1, tc.name)
		require.Empty(t, h.replies, tc.name)
		frames := h.produced[0].decoded.([]parsedRPCBind)
		require.Len(t, frames, 1, tc.name)
		require.Equal(t, tc.cmd, frames[0].Command, tc.name)
		require.Equal(t, len(tc.data) > maxRPCBindPayload, frames[0].Truncated, tc.name)
		require.LessOrEqual(t, len(frames[0].Payload), maxRPCBindPayload, tc.name)
	}
}

func TestHandleRPCBindUDPCallitCaptured(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := rpcbindAddrs()
	// v2 CALLIT (no record mark over UDP) asking the portmapper to relay to
	// nlockmgr (100021 v4): the target is captured, but nothing is relayed and
	// no reply is sent.
	callit := rpcbindWords(0x2a, 0, 2, 100000, 2, 5, 0, 0, 0, 0, 100021, 4, 0, 0)
	require.NoError(t, HandleRPCBind(context.Background(), src, dst, callit, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedRPCBind{
		{Direction: "read", Command: "PMAPPROC_CALLIT", XID: 0x2a, Program: 100000, Version: 2, Procedure: 5, Auth: "AUTH_NONE", TargetProgram: 100021, TargetVersion: 4, Payload: callit},
	}, h.produced[0].decoded)
}

// APCO Sys truncated rpcbind v4 DUMP (Ochi event e773c076-56e9-4cc4-ae39-8e8ac4ce6a46).
// Missing the 8-byte empty AUTH_NONE verifier; decode the header, do not reply.
var rpcbindApcoRead1 = []byte("\x124Vx\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00")

func TestHandleRPCBindUDPTruncatedDump(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := rpcbindAddrs()

	require.NoError(t, HandleRPCBind(context.Background(), src, dst, rpcbindApcoRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "rpcbind", h.produced[0].handler)
	require.Equal(t, rpcbindApcoRead1, h.produced[0].payload)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedRPCBind{
		{
			Direction: "read", Command: "RPCBPROC_DUMP", XID: 0x12345678,
			Program: 100000, Version: 4, Procedure: 4, Auth: "AUTH_NONE",
			Payload: rpcbindApcoRead1,
		},
	}, h.produced[0].decoded)
}
