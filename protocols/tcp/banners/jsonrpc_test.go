package banners

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanInitialize is the probe Shodan sent to tcp/2087 (2026-11-07 11:04:15 UTC).
var shodanInitialize = []byte("Content-Length: 65\r\n\r\n" +
	`{"params": {}, "jsonrpc": "2.0", "id": 1, "method": "initialize"}`)

// decodeJSONRPCFrames splits a reply into its framed JSON bodies.
func decodeJSONRPCFrames(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for len(data) > 0 {
		body, rest, ok := splitJSONRPCFrame(data)
		require.True(t, ok, "%q", data)
		var msg map[string]any
		require.NoError(t, json.Unmarshal(body, &msg))
		out = append(out, msg)
		data = rest
	}
	return out
}

func TestJSONRPCInitialize(t *testing.T) {
	resp, ok := ForPayload(shodanInitialize)
	require.True(t, ok)
	require.Equal(t, "jsonrpc", resp.Name)
	require.False(t, resp.NoReply)

	want := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",` +
		`"capabilities":{"prompts":{"listChanged":false},"resources":{"listChanged":false,"subscribe":false},"tools":{"listChanged":false}},` +
		`"serverInfo":{"name":"mcp","version":"1.0.0"}}}`
	require.Equal(t, "Content-Length: "+strconv.Itoa(len(want))+"\r\n\r\n"+want, string(resp.Data))
}

func TestJSONRPCInitializeEchoesClientVersionAndID(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"a7","method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	data := []byte("content-length: " + strconv.Itoa(len(body)) + "\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n" + body)
	resp, ok := jsonrpcReply(data)
	require.True(t, ok)
	msgs := decodeJSONRPCFrames(t, resp.Data)
	require.Len(t, msgs, 1)
	require.Equal(t, "a7", msgs[0]["id"])
	require.Equal(t, "2024-11-05", msgs[0]["result"].(map[string]any)["protocolVersion"])
}

func TestJSONRPCFollowUps(t *testing.T) {
	frame := func(s string) string { return "Content-Length: " + strconv.Itoa(len(s)) + "\r\n\r\n" + s }

	// a lone notification gets no reply, but the session stays open
	resp, ok := jsonrpcReply([]byte(frame(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
	require.True(t, ok)
	require.Equal(t, Response{Name: "jsonrpc", NoReply: true}, resp)

	// a notification coalesced with requests: only the requests are answered
	resp, ok = jsonrpcReply([]byte(frame(`{"jsonrpc":"2.0","method":"notifications/initialized"}`) +
		frame(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`) +
		frame(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`)))
	require.True(t, ok)
	msgs := decodeJSONRPCFrames(t, resp.Data)
	require.Len(t, msgs, 2)
	require.EqualValues(t, 2, msgs[0]["id"])
	require.Len(t, msgs[0]["result"].(map[string]any)["tools"], 1)
	require.EqualValues(t, 3, msgs[1]["id"])
	require.Equal(t, map[string]any{"code": float64(-32601), "message": "Method not found"}, msgs[1]["error"])
}

func TestJSONRPCRejects(t *testing.T) {
	for _, data := range [][]byte{
		shodanInitialize[:len(shodanInitialize)-1],                                 // body cut short
		[]byte("Content-Length: 2\r\n\r\n{}"),                                      // not JSON-RPC
		[]byte("Content-Length: 30\r\n\r\n{\"jsonrpc\":\"1.0\",\"method\":\"x\"}"), // wrong version
		[]byte("Content-Length: x\r\n\r\n{}"),
		[]byte("Content-Type: text/plain\r\n\r\n{}"),             // no length
		[]byte("POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"), // HTTP request line
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`), // unframed
		[]byte(""),
	} {
		_, ok := jsonrpcReply(data)
		require.False(t, ok, "%q", data)
	}
}
