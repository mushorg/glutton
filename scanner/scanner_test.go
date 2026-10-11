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
}
