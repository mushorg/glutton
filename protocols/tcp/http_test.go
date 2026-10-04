package tcp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestFormatRequest(t *testing.T) {
	mockReq, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)
	require.Equal(t, "GET http://example.com HTTP/1.1\nHost: example.com", formatRequest(mockReq))
}

func withHTTPSessionIdle(t *testing.T, idle time.Duration) {
	t.Helper()
	prev := sessionIdle
	sessionIdle = idle
	t.Cleanup(func() {
		sessionIdle = prev
		httpSessions.reset()
		mcpSessions.reset()
	})
}

func httpTestRequest(method, path, sessionID string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	b.WriteString("Host: 127.0.0.1\r\n")
	b.WriteString("User-Agent: test-agent/1.0\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	if sessionID != "" {
		fmt.Fprintf(&b, "Cookie: %s=%s\r\n", httpSessionCookie, sessionID)
	}
	if body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	out := []byte(b.String())
	if body != nil {
		out = append(out, body...)
	}
	return out
}

func TestHandleHTTPKeepAliveOneEvent(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/", "", nil))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	sessionID := sessionCookieFromHeaders(t, headers)
	require.NotEmpty(t, sessionID)

	_, err = client.Write(httpTestRequest("GET", "/wallet", sessionID, nil))
	require.NoError(t, err)
	status, _, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), `[[""]]`)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 4)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "GET", events[0].Command)
	require.Equal(t, "/", events[0].Path)
	require.Equal(t, "127.0.0.1", events[0].Host)
	require.Equal(t, "test-agent/1.0", events[0].UserAgent)
	require.Equal(t, sessionID, events[0].SessionID)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
	require.Equal(t, sessionID, events[1].SessionID)
	require.Equal(t, "/wallet", events[2].Path)
}

func TestHandleHTTPSessionGroupsAcrossConnections(t *testing.T) {
	withHTTPSessionIdle(t, 80*time.Millisecond)

	hp := newFakeHoneypot()

	client1, server1 := net.Pipe()
	done1 := make(chan error, 1)
	go func() {
		done1 <- HandleHTTP(context.Background(), server1, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err := client1.Write(httpTestRequest("GET", "/", "", nil))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client1)
	require.Equal(t, http.StatusOK, status)
	sessionID := sessionCookieFromHeaders(t, headers)
	require.NotEmpty(t, sessionID)
	require.NoError(t, client1.Close())
	require.NoError(t, <-done1)

	select {
	case extra := <-hp.produced:
		t.Fatalf("expected no event before session idle, got: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}

	client2, server2 := net.Pipe()
	done2 := make(chan error, 1)
	go func() {
		done2 <- HandleHTTP(context.Background(), server2, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err = client2.Write(httpTestRequest("GET", "/api", sessionID, nil))
	require.NoError(t, err)
	status, _, _ = readHTTPResponse(t, client2)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, client2.Close())
	require.NoError(t, <-done2)

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single session event, got another: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}

	events := produced.decoded.([]parsedHTTP)
	require.GreaterOrEqual(t, len(events), 4)
	require.Equal(t, "/", events[0].Path)
	require.Equal(t, sessionID, events[0].SessionID)
	require.Equal(t, "/api", events[2].Path)
	require.Equal(t, sessionID, events[2].SessionID)
}

func TestHandleHTTPEarlyDisconnect(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	select {
	case extra := <-hp.produced:
		t.Fatalf("connect-only probe should not produce an event, got: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleHTTPHandsOffMCP(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err := client.Write(mcpInitializeRequest(1))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, headers.Get("Mcp-Session-Id"))
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "mcp", produced.protocol)
	_, ok := produced.decoded.([]parsedMCP)
	require.True(t, ok)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected no HTTP event after MCP handoff, got: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func sessionCookieFromHeaders(t *testing.T, headers http.Header) string {
	t.Helper()
	for _, c := range headers.Values("Set-Cookie") {
		if strings.HasPrefix(c, httpSessionCookie+"=") {
			val := strings.TrimPrefix(c, httpSessionCookie+"=")
			if i := strings.IndexByte(val, ';'); i >= 0 {
				val = val[:i]
			}
			return val
		}
	}
	return ""
}
