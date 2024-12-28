package glutton

import (
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSetTProxyNFTables(t *testing.T) {
	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range req {
				b, err := msg.MarshalBinary()
				require.NoError(t, err, "failed to marshal netlink message")
				require.NotEmpty(t, b, "empty netlink message")
			}
			return req, nil
		}))
	require.NoError(t, err, "failed to create nftables.Conn")

	_, err = setTProxyNFTables(c, 5000, 22, unix.IPPROTO_TCP, "eth0")
	require.NoError(t, err, "failed to set TCP TPROXY nftables rule")

	_, err = setTProxyNFTables(c, 5001, 22, unix.IPPROTO_UDP, "eth0")
	require.NoError(t, err, "failed to set UDP TPROXY nftables rule")
}

func TestNFTablesConnection(t *testing.T) {
	c, err := nftables.New()
	require.NoError(t, err, "failed to create nftables.Conn")

	tables, err := c.ListTables()
	require.NoError(t, err, "failed to list nftables tables")
	require.NotEmpty(t, tables, "no nftables tables found")
}
