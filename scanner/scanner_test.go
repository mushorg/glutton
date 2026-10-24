package scanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyKnownScannerNoPTR(t *testing.T) {
	name, ptr, err := Classify(net.ParseIP("162.142.125.1"))
	require.NoError(t, err)
	require.Equal(t, "censys", name)
	require.Empty(t, ptr)
}

func TestScannerSubnetsCanonical(t *testing.T) {
	// net.ParseCIDR silently masks host bits, so "a.b.c.56/26" would match
	// a.b.c.0/26; require every entry to be written as its network address.
	for name, subnets := range scannerSubnet {
		for _, subnet := range subnets {
			_, network, err := net.ParseCIDR(subnet)
			require.NoError(t, err, name)
			require.Equal(t, network.String(), subnet, name)
		}
	}
}

func TestClassifyRWTH(t *testing.T) {
	name, _, err := Classify(net.ParseIP("137.226.113.44"))
	require.NoError(t, err)
	require.Equal(t, "rwth", name)
}

func TestIsScanner(t *testing.T) {
	matched, _, err := IsScanner(net.ParseIP("162.142.125.1"))
	require.NoError(t, err)
	require.True(t, matched, "IP should be a scanner")
}

func TestClassifyPayload(t *testing.T) {
	const h = "0003c8efa0acdc0c6540f4bdb920f6bcabdd01d0ed98e0f21938144c44e121a5"
	require.Equal(t, "rdp-nla-prober", ClassifyPayload("rdp", h))
	require.Empty(t, ClassifyPayload("tcp", h))
	require.Empty(t, ClassifyPayload("rdp", "deadbeef"))

	const socksHash = "b211715c04660f10841bbd1315b6ca7a4f4c755d1127f5c59d7122ae51a6eb13"
	require.Equal(t, "socks-http-flood", ClassifyPayload("socks", socksHash))
	require.Empty(t, ClassifyPayload("tcp", socksHash))
}

func TestClassifyTLS(t *testing.T) {
	const ja4 = "t12d320800_a6df2e0e78d0_36cef8aed422"
	require.Equal(t, "socks-https-flood", ClassifyTLS("socks", ja4))
	require.Empty(t, ClassifyTLS("http", ja4))
	require.Empty(t, ClassifyTLS("socks", "t13d1516h2_8daaf6152771_02713d6af862"))
	require.Empty(t, ClassifyTLS("socks", ""))
}
