package protocols

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPeek(t *testing.T) {
	conn, close := testConn(t)
	defer close()
	snip, _, err := Peek(conn, 1)
	var netErr net.Error
	ok := errors.As(err, &netErr)
	require.True(t, ok)
	require.True(t, netErr.Timeout())
	require.Empty(t, snip)
}
