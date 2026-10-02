package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func mcpInitializeRequest(id int) []byte {
	body := []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}`)
	return mcpHTTPRequest("POST", "/mcp", body)
}

func mcpHTTPRequest(method, path string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	b.WriteString("Host: 127.0.0.1\r\n")
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Accept: application/json, text/event-stream\r\n")
	b.WriteString("Connection: keep-alive\r\n")
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

func readHTTPResponse(t *testing.T, client net.Conn) (status int, headers http.Header, body []byte) {
	t.Helper()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, body
}

func TestLooksLikeMCP(t *testing.T) {
	require.True(t, LooksLikeMCP([]byte("POST /mcp HTTP/1.1\r\n")))
	require.True(t, LooksLikeMCP([]byte("GET /mcp?session=1 HTTP/1.1\r\n")))
	require.True(t, LooksLikeMCP([]byte("POST /sse HTTP/1.1\r\n")))
	require.False(t, LooksLikeMCP([]byte("POST /api HTTP/1.1\r\n")))
	require.False(t, LooksLikeMCP([]byte("GET / HTTP/1.1\r\n")))
}

func TestIsMCPPath(t *testing.T) {
	require.True(t, IsMCPPath("/mcp"))
	require.True(t, IsMCPPath("/mcp/"))
	require.True(t, IsMCPPath("/MCP"))
	require.True(t, IsMCPPath("/sse"))
	require.True(t, IsMCPPath("/mcp?x=1"))
	require.False(t, IsMCPPath("/api"))
	require.False(t, IsMCPPath("/"))
}

func TestHandleMCPInitializeAndToolsList(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- handleMCP(context.Background(), newMCPServer(serverConn), connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(mcpInitializeRequest(9067582))
	require.NoError(t, err)

	status, headers, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, mcpSessionID, headers.Get("Mcp-Session-Id"))

	var initResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &initResp))
	require.Equal(t, "2.0", initResp.JSONRPC)
	require.Equal(t, 9067582, initResp.ID)
	require.Equal(t, "2025-06-18", initResp.Result.ProtocolVersion)
	require.Equal(t, mcpServerName, initResp.Result.ServerInfo.Name)

	notif := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	_, err = client.Write(mcpHTTPRequest("POST", "/mcp", notif))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusAccepted, status)
	require.Empty(t, body)

	toolsBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	_, err = client.Write(mcpHTTPRequest("POST", "/mcp", toolsBody))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), `"name":"echo"`)

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "mcp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedMCP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 5) // init read/write, notif read/write, tools read/write
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "initialize", events[0].Command)
	require.Equal(t, "/mcp", events[0].Path)
	require.True(t, bytes.Contains(events[0].Payload, []byte("initialize")))

	require.Equal(t, "write", events[1].Direction)
	require.True(t, bytes.Contains(events[1].Payload, []byte(mcpServerName)))

	require.Equal(t, "notifications/initialized", events[2].Command)
	require.Equal(t, "tools/list", events[4].Command)
}

func TestHandleMCPEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- handleMCP(context.Background(), newMCPServer(serverConn), connection.Metadata{}, &recordingLogger{}, hp)
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

func TestHandleMCPCensusScannerPayload(t *testing.T) {
	// Mirrors the internet-census-mcp-scanner probe seen in the wild.
	body := []byte(`{"jsonrpc":"2.0","id":9067582,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{},"elicitation":{},"roots":{"listChanged":true}},"clientInfo":{"name":"internet-census-mcp-scanner","version":"1.0.0"}}}`)
	raw := mcpHTTPRequest("POST", "/mcp", body)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMCP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(raw)
	require.NoError(t, err)

	status, headers, respBody := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, mcpSessionID, headers.Get("Mcp-Session-Id"))
	require.Contains(t, string(respBody), `"protocolVersion":"2025-06-18"`)
	require.Contains(t, string(respBody), `"name":"glutton-mcp"`)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedMCP)
	require.Equal(t, "initialize", events[0].Command)
	require.True(t, bytes.Contains(events[0].Payload, []byte("internet-census-mcp-scanner")))
}

func TestPrependConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("world"))
		_ = client.Close()
	}()

	pc := PrependConn(server, []byte("hello"))
	got, err := io.ReadAll(pc)
	require.NoError(t, err)
	require.Equal(t, "helloworld", string(got))
}
