package wdb

import (
	"encoding/binary"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/stretchr/testify/require"
)

// Censys WDB_TARGET_CONNECT to udp/17185 (captured 2026-11-06, 66.132.224.22).
var censysConnect = []byte{
	0x1a, 0x09, 0xfa, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x55, 0x55, 0x55, 0x55,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x55, 0x12, 0x00, 0x00, 0x00, 0x3c,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestParseCensysConnect(t *testing.T) {
	c, err := oncrpc.Parse(censysConnect)
	require.NoError(t, err)
	require.Equal(t, uint32(Program), c.Program)
	require.Equal(t, uint32(ProcConnect), c.Procedure)
	require.Equal(t, "WDB_TARGET_CONNECT", ProcName(c.Procedure))

	w, err := ParseWrapper(c.Args)
	require.NoError(t, err)
	require.Equal(t, uint32(0xffff5512), w.Checksum)
	require.Equal(t, uint32(len(censysConnect)-4), w.Size)
	require.Equal(t, uint32(1), w.Seq)
	require.Equal(t, []byte{0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0}, w.Args)

	// The scanner's checksum verifies with our formula.
	require.Equal(t, uint16(0x5512), Checksum(censysConnect, 40))
}

func TestParseWrapperShort(t *testing.T) {
	_, err := ParseWrapper([]byte{0xff, 0xff, 0, 0})
	require.ErrorIs(t, err, ErrShortWrapper)
}

func TestReplyConnect(t *testing.T) {
	c, err := oncrpc.Parse(censysConnect)
	require.NoError(t, err)
	b, status := Reply(c, DefaultTarget)
	require.Equal(t, "SUCCESS", status)

	// Accepted RPC reply echoing the XID, AUTH_NONE verifier, SUCCESS.
	require.Equal(t, uint32(0x1a09faba), binary.BigEndian.Uint32(b))
	for i, want := range []uint32{oncrpc.MsgReply, 0, 0, 0, 0} {
		require.Equal(t, want, binary.BigEndian.Uint32(b[4+4*i:]), "word %d", i+1)
	}
	// Reply wrapper: checksum verifies, size, errCode 0.
	require.Equal(t, uint32(0xffff0000|uint32(Checksum(b, 24))), binary.BigEndian.Uint32(b[24:]))
	require.Equal(t, uint32(len(b)-4), binary.BigEndian.Uint32(b[28:]))
	require.Equal(t, uint32(0), binary.BigEndian.Uint32(b[32:]))
	// Agent version string, then MTU.
	require.Equal(t, uint32(3), binary.BigEndian.Uint32(b[36:]))
	require.Equal(t, "2.0", string(b[40:43]))
	require.Equal(t, uint32(1500), binary.BigEndian.Uint32(b[44:]))
	require.Contains(t, string(b), "5.5.1")
	require.Contains(t, string(b), "Wind River SBC8260")
	require.Zero(t, len(b)%4)
}

func TestReplyOutcomes(t *testing.T) {
	base := oncrpc.Call{XID: 7, MsgType: oncrpc.MsgCall, RPCVersion: 2, Program: Program, Version: Version, Header: true}
	for _, tc := range []struct {
		name   string
		mut    func(*oncrpc.Call)
		status string
		len    int
	}{
		{"ping", func(c *oncrpc.Call) { c.Procedure = ProcPing }, "SUCCESS", 36},
		{"disconnect", func(c *oncrpc.Call) { c.Procedure = ProcDisconnect }, "SUCCESS", 36},
		{"mem read", func(c *oncrpc.Call) { c.Procedure = 10 }, "PROC_UNAVAIL", 24},
		{"other program", func(c *oncrpc.Call) { c.Program = 100000 }, "PROG_UNAVAIL", 24},
		{"bad version", func(c *oncrpc.Call) { c.Version = 2 }, "PROG_MISMATCH", 32},
		{"rpc v3", func(c *oncrpc.Call) { c.RPCVersion = 3 }, "RPC_MISMATCH", 24},
	} {
		c := base
		tc.mut(&c)
		b, status := Reply(&c, DefaultTarget)
		require.Equal(t, tc.status, status, tc.name)
		require.Len(t, b, tc.len, tc.name)
		require.Equal(t, uint32(7), binary.BigEndian.Uint32(b), tc.name)
	}

	b, status := Reply(&oncrpc.Call{XID: 1, MsgType: oncrpc.MsgReply}, DefaultTarget)
	require.Nil(t, b)
	require.Empty(t, status)
	b, _ = Reply(&oncrpc.Call{XID: 1, MsgType: oncrpc.MsgCall}, DefaultTarget)
	require.Nil(t, b, "no header, no reply")
	require.Equal(t, "WDB_PROC_99", ProcName(99))
}
