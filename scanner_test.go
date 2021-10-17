package glutton

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsScanner(t *testing.T) {
	matched, _ := isScanner(net.ParseIP("162.142.125.1"))
	require.True(t, matched, "IP should be a scanner")
}
