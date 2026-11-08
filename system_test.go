package glutton

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetNonLoopbackIPs(t *testing.T) {
	_, err := getNonLoopbackIPs("glutton-no-such-if0")
	require.Error(t, err)

	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		ips, err := getNonLoopbackIPs(iface.Name)
		if err != nil {
			require.ErrorContains(t, err, "unable to find any non-loopback addresses", iface.Name)
			continue
		}
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		for _, ip := range ips {
			require.NotNil(t, ip.To4(), iface.Name)
			require.False(t, ip.IsLoopback(), iface.Name)
			found := false
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
					found = true
				}
			}
			require.True(t, found, "%s not on %s", ip, iface.Name)
		}
	}
}
