package glutton

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	server := NewServer(1234, 1235)
	require.NotNil(t, server)
	err := server.Shutdown()
	require.NoError(t, err)
}
