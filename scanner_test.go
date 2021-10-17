package glutton

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsScanner(t *testing.T) {
	require.True(t, isScanner(net.ParseIP("162.142.125.1")), "IP should be a scanner")
}
