package protocols

import (
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/adb"
	"github.com/stretchr/testify/require"
)

func TestADBTargetRoutesTransport(t *testing.T) {
	names := dispatchTarget(t, "adb", 5555, func(c net.Conn) {
		_, err := c.Write(adb.Build(adb.CmdCNXN, 0x01000000, 4096, []byte("host::\x00")))
		require.NoError(t, err)
		msg, _, err := adb.ReadMessage(c, adb.MaxPayload)
		require.NoError(t, err)
		require.Equal(t, "CNXN", msg.Name())
	})
	require.Equal(t, []string{"adb"}, names)
}

func TestADBTargetRoutesHostRequest(t *testing.T) {
	names := dispatchTarget(t, "adb", 5037, func(c net.Conn) {
		_, err := c.Write([]byte("000chost:version"))
		require.NoError(t, err)
		_, _ = io.ReadAll(c)
	})
	require.Equal(t, []string{"adb"}, names)
}

func TestADBTargetFallsBackToTCP(t *testing.T) {
	names := dispatchTarget(t, "adb", 5555, func(c net.Conn) {
		_, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestADBTargetSilentClientNoEvent(t *testing.T) {
	names := dispatchTarget(t, "adb", 5555, func(net.Conn) {})
	require.Empty(t, names)
}

func TestCatchAllRoutesADBTransport(t *testing.T) {
	ev := dispatchCatchAll(t, 15555, func(c net.Conn) {
		_, err := c.Write(adb.Build(adb.CmdCNXN, 0x01000000, 4096, []byte("host::\x00")))
		require.NoError(t, err)
		msg, _, err := adb.ReadMessage(c, adb.MaxPayload)
		require.NoError(t, err)
		require.Equal(t, "CNXN", msg.Name())
	})
	require.Equal(t, "adb", ev.protocol)
	require.Equal(t, "CNXN", ev.frames[0]["packet"])
	require.Equal(t, "host::", ev.frames[0]["identity"])
}

func TestCatchAllNonADBStaysTCP(t *testing.T) {
	// the CNXN bytes in the wrong order are not an ADB command
	ev := dispatchCatchAll(t, 15555, func(c net.Conn) {
		_, err := c.Write([]byte("NXNC\r\n"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
}
