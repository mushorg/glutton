package protocols

import (
	"bufio"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/rsync"
	"github.com/stretchr/testify/require"
)

// sendRsyncVersion writes the version line from the tcp/873 catch-all event
// (134.185.88.23, 2026-10-24) and checks the daemon greeting.
func sendRsyncVersion(t *testing.T) func(net.Conn) {
	return func(c net.Conn) {
		_, err := c.Write([]byte("@RSYNCD: 31.0\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, rsync.Greeting, line)
	}
}

func TestCatchAllRoutesRsync(t *testing.T) {
	names := dispatchTarget(t, "tcp", 8730, sendRsyncVersion(t))
	require.Equal(t, []string{"rsync"}, names)
}

func TestRsyncTarget(t *testing.T) {
	names := dispatchTarget(t, "rsync", 873, sendRsyncVersion(t))
	require.Equal(t, []string{"rsync"}, names)
}

func TestCatchAllKeepsNonRsync(t *testing.T) {
	names := dispatchTarget(t, "tcp", 8730, func(c net.Conn) {
		_, err := c.Write([]byte("@RSYNC-ish but not a version line\n"))
		require.NoError(t, err)
	})
	require.Equal(t, []string{"tcp"}, names)
}
