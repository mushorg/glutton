//go:build linux

package glutton

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDialTProxyUDP(t *testing.T) {
	// a free port stands in for the original destination of the packets
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	laddr := free.LocalAddr().(*net.UDPAddr)
	require.NoError(t, free.Close())

	// two sources answered from the same address at once
	for range 2 {
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		defer peer.Close()

		conn, err := dialTProxyUDP(laddr, peer.LocalAddr().(*net.UDPAddr))
		if errors.Is(err, syscall.EPERM) {
			t.Skip("IP_TRANSPARENT needs CAP_NET_ADMIN")
		}
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("pong"))
		require.NoError(t, err)

		buf := make([]byte, 16)
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := peer.ReadFromUDP(buf)
		require.NoError(t, err)
		require.Equal(t, "pong", string(buf[:n]))
		require.Equal(t, laddr.String(), from.String(), "the reply leaves from the bound address")
	}
}
