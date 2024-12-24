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

	err = setTProxyNFTables(c, 5000, unix.IPPROTO_TCP)
	require.NoError(t, err, "failed to set TCP TPROXY nftables rule")

	err = setTProxyNFTables(c, 5001, unix.IPPROTO_UDP)
	require.NoError(t, err, "failed to set UDP TPROXY nftables rule")
}
