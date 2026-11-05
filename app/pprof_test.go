package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenPprofRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:6060", ":6060", "10.0.0.1:6060", "example.com:6060", "127.0.0.1"} {
		_, err := listenPprof(addr)
		require.Error(t, err, addr)
	}
}

func TestStartPprofServesHeapProfile(t *testing.T) {
	ln, err := startPprof("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/debug/pprof/heap?debug=1")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(body), "heap profile"), "heap profile body")
}
