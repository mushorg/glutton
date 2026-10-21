package protocols

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Censys ONC RPC CALL for program 6969 sent to tcp/27488 (Ochi event
// 2026-10-21T19:05:27Z).
var rpcScannerProbe = []byte("\x80\x00\x00\x28\xca\xfe\xca\xfe\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x1b\x39\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

func TestCatchAllRoutesOffPortRPC(t *testing.T) {
	ev := dispatchCatchAll(t, 27488, func(c net.Conn) {
		_, err := c.Write(rpcScannerProbe)
		require.NoError(t, err)
		reply := make([]byte, 28)
		_, err = io.ReadFull(c, reply)
		require.NoError(t, err)
		require.Equal(t, uint32(0x80000018), binary.BigEndian.Uint32(reply))
		require.Equal(t, uint32(0xcafecafe), binary.BigEndian.Uint32(reply[4:]))
		require.Equal(t, uint32(1), binary.BigEndian.Uint32(reply[24:])) // PROG_UNAVAIL
	})
	require.Equal(t, "rpcbind", ev.protocol)
	require.Equal(t, float64(0x1b39), ev.frames[0]["program"])
	require.Equal(t, "PROG_UNAVAIL", ev.frames[1]["status"])
}

func TestCatchAllNonRPCStaysTCP(t *testing.T) {
	ev := dispatchCatchAll(t, 27488, func(c net.Conn) {
		_, err := c.Write([]byte("\x80\x00\x00\x28\xca\xfe\xca\xfe\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x1b\x39"))
		require.NoError(t, err)
		_, err = c.Read(make([]byte, 4096))
		require.NoError(t, err)
	})
	require.Equal(t, "tcp", ev.protocol)
}
