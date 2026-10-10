package protocols

import (
	"bufio"
	"net"
	"testing"

	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"
	"github.com/stretchr/testify/require"
)

// sendSSHVersion writes a client identification string and checks the
// server's.
func sendSSHVersion(t *testing.T) func(net.Conn) {
	return func(c net.Conn) {
		// read frame 1 of ochi event b40b00cd-6c5c-40c7-8e6a-c91b8b9d2ce4 (tcp/122)
		_, err := c.Write([]byte("SSH-2.0-paramiko_2.11.0\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, sshproto.ServerVersion+"\r\n", line)
	}
}

func TestCatchAllRoutesSSH(t *testing.T) {
	names := dispatchTarget(t, "tcp", 122, sendSSHVersion(t))
	require.Equal(t, []string{"ssh"}, names)
}

func TestSSHTarget(t *testing.T) {
	names := dispatchTarget(t, "ssh", 22, sendSSHVersion(t))
	require.Equal(t, []string{"ssh"}, names)
}
