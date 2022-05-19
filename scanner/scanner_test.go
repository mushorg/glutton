package scanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsScanner(t *testing.T) {
	matched, _, err := IsScanner(net.ParseIP("162.142.125.1"))
	require.NoError(t, err)
	require.True(t, matched, "IP should be a scanner")
}
