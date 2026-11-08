package protocols

import (
	"bufio"
	"io"
	"net"
	"strings"
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

func TestADBTargetFallsBackToCatchAll(t *testing.T) {
	// HTTP on an ADB port reaches the HTTP handler through the catch-all;
	// instead of the generic fallback
	ev := dispatchCatchAllTarget(t, "adb", 5555, func(c net.Conn) {
		_, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(line, "HTTP/1.1 "), line)
	})
	require.Equal(t, "http", ev.protocol)

	names := dispatchTarget(t, "adb", 5555, func(c net.Conn) {
		_, err := c.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestADBTargetRoutesRDP(t *testing.T) {
	// RDP X.224 CR + RDP_NEG_REQ (requestedProtocols=3) captured on tcp/5555
	// on 2026-11-08; the generic fallback left it unanswered
	cr := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	names := dispatchTarget(t, "adb", 5555, func(c net.Conn) {
		_, err := c.Write(cr)
		require.NoError(t, err)
		reply := make([]byte, 19)
		_, err = io.ReadFull(c, reply)
		require.NoError(t, err)
		// Connection Confirm with RDP_NEG_RSP
		require.Equal(t, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0}, reply[:6])
		require.Equal(t, byte(0x02), reply[11])
	})
	require.Equal(t, []string{"rdp"}, names)
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
