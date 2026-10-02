package glutton

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerStartReportsTProxyErrors(t *testing.T) {
	server := NewServer(15000, 15001)
	err := server.Start()
	// Without CAP_NET_ADMIN this should fail with a real error (not succeed with a nil listener).
	if err == nil {
		require.NotNil(t, server.tcpListener, "tcpListener must not be nil when Start succeeds")
		_ = server.tcpListener.Close()
		if server.udpConn != nil {
			_ = server.udpConn.Close()
		}
		t.Skip("TPROXY socket options succeeded; cannot assert failure path on this host")
	}
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "IP_TRANSPARENT") || strings.Contains(err.Error(), "permission"),
		"expected IP_TRANSPARENT/permission error, got: %v", err)
	require.Nil(t, server.tcpListener)
}
