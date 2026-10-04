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
