package selenium

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// greedBody is shaped like the SeleniumGreed new-session request (Wiz,
// 2024): python3 as the Chrome binary with a base64 one-liner in args. The
// payload here is a harmless "import os". Synthetic, not captured.
const greedBody = `{"capabilities":{"alwaysMatch":{"browserName":"chrome",` +
	`"goog:chromeOptions":{"binary":"/usr/bin/python3",` +
	`"args":["-cimport base64;exec(base64.b64decode(b'aW1wb3J0IG9z'))"]}}}}`

func fixedGrid(t *testing.T) {
	t.Helper()
	prev := Grid
	Grid = Identity{
		NodeID: "5b0c6f2e-1d7a-4c39-9a51-3f0e8c2b7d14",
		SlotID: "9e4f1a73-2b6c-4d08-8f35-c71a0d9e6b52",
		Host:   "3f9a1c7e2b4d",
		IP:     "172.17.0.2",
	}
	t.Cleanup(func() { Grid = prev })
}

// split returns the status line, headers and body of a response, and checks
// Content-Length.
func split(t *testing.T, resp []byte) (string, string, []byte) {
	t.Helper()
	head, body, ok := bytes.Cut(resp, []byte("\r\n\r\n"))
	require.True(t, ok, "%q", resp)
	status, headers, _ := strings.Cut(string(head), "\r\n")
	require.Contains(t, headers, "Content-Length: "+strconv.Itoa(len(body)))
	return status, headers, body
}

func gridValue(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var v struct {
		Value map[string]any `json:"value"`
	}
	require.NoError(t, json.Unmarshal(body, &v), "%s", body)
	return v.Value
}

func TestIsGridRequest(t *testing.T) {
	require.True(t, IsGridRequest(4444, "/"))
	require.True(t, IsGridRequest(4444, "/anything"))
	require.True(t, IsGridRequest(80, "/wd/hub/status"))
	require.True(t, IsGridRequest(8080, "/wd/hub"))
	require.False(t, IsGridRequest(80, "/status"))
	require.False(t, IsGridRequest(80, "/wd/hubx"))
}

func TestStatus(t *testing.T) {
	fixedGrid(t)
	for _, path := range []string{"/status", "/wd/hub/status"} {
		status, headers, body := split(t, Respond("GET", path, nil))
		require.Equal(t, "HTTP/1.1 200 OK", status)
		require.Contains(t, headers, "Content-Type: application/json; charset=utf-8")
		// Selenium's JSON escapes '/'
		require.Contains(t, string(body), `"uri": "http:`+escapedSlash+escapedSlash+`172.17.0.2:4444"`)
		require.NotContains(t, string(body), "/")

		v := gridValue(t, body)
		require.Equal(t, true, v["ready"])
		require.Equal(t, "Selenium Grid ready.", v["message"])
		nodes := v["nodes"].([]any)
		require.Len(t, nodes, 1)
		n := nodes[0].(map[string]any)
		require.Equal(t, "5b0c6f2e-1d7a-4c39-9a51-3f0e8c2b7d14", n["id"])
		require.Equal(t, "UP", n["availability"])
		require.Equal(t, "4.45.0 (revision cd6a3cdfca)", n["version"])
		st := n["slots"].([]any)[0].(map[string]any)["stereotype"].(map[string]any)
		require.Equal(t, "chrome", st["browserName"])
	}
}

func TestRootRedirectsToUI(t *testing.T) {
	status, headers, body := split(t, Respond("GET", "/", nil))
	require.Equal(t, "HTTP/1.1 302 Found", status)
	require.Contains(t, headers, "Location: /ui/")
	require.Empty(t, body)

	status, _, body = split(t, Respond("GET", "/ui/", nil))
	require.Equal(t, "HTTP/1.1 200 OK", status)
	require.Contains(t, string(body), "<title>Selenium Grid</title>")
}

func TestNewSessionRequest(t *testing.T) {
	s, ok := NewSessionRequest("POST", "/wd/hub/session", []byte(greedBody))
	require.True(t, ok)
	require.Equal(t, NewSession{
		Browser: "chrome",
		Binary:  "/usr/bin/python3",
		Args:    []string{"-cimport base64;exec(base64.b64decode(b'aW1wb3J0IG9z'))"},
	}, s)

	// legacy desiredCapabilities, firefox options
	legacy := `{"desiredCapabilities":{"browserName":"firefox","moz:firefoxOptions":{"binary":"/bin/sh","args":["-c","id"]}}}`
	s, ok = NewSessionRequest("POST", "/session/", []byte(legacy))
	require.True(t, ok)
	require.Equal(t, NewSession{Browser: "firefox", Binary: "/bin/sh", Args: []string{"-c", "id"}}, s)

	// alwaysMatch wins over firstMatch
	merged := `{"capabilities":{"firstMatch":[{"browserName":"firefox"}],"alwaysMatch":{"browserName":"chrome"}}}`
	s, ok = NewSessionRequest("POST", "/session", []byte(merged))
	require.True(t, ok)
	require.Equal(t, "chrome", s.Browser)

	for _, c := range []struct{ method, path, body string }{
		{"GET", "/session", greedBody},
		{"POST", "/status", greedBody},
		{"POST", "/session/abc/url", greedBody},
		{"POST", "/session", "not json"},
	} {
		_, ok := NewSessionRequest(c.method, c.path, []byte(c.body))
		require.False(t, ok, "%+v", c)
	}
}

func TestNewSessionCaps(t *testing.T) {
	args := make([]string, maxArgs+5)
	for i := range args {
		args[i] = "a"
	}
	args[0] = strings.Repeat("x", maxArgLen+10)
	opts, err := json.Marshal(map[string]any{"binary": strings.Repeat("b", maxBinaryLen+1), "args": args})
	require.NoError(t, err)
	body := `{"capabilities":{"alwaysMatch":{"goog:chromeOptions":` + string(opts) + `}}}`

	s, ok := NewSessionRequest("POST", "/session", []byte(body))
	require.True(t, ok)
	require.True(t, s.Truncated)
	require.Len(t, s.Args, maxArgs)
	require.Len(t, s.Args[0], maxArgLen)
	require.Len(t, s.Binary, maxBinaryLen)
}

func TestNewSessionFailsLikeCrashedChrome(t *testing.T) {
	fixedGrid(t)
	status, _, body := split(t, Respond("POST", "/wd/hub/session", []byte(greedBody)))
	require.Equal(t, "HTTP/1.1 500 Internal Server Error", status)
	v := gridValue(t, body)
	require.Equal(t, "session not created", v["error"])
	msg := v["message"].(string)
	require.Contains(t, msg, "Chrome failed to start: exited normally.")
	require.Contains(t, msg, "chrome location /usr/bin/python3 is no longer running")
	require.Contains(t, msg, "Host info: host: '3f9a1c7e2b4d', ip: '172.17.0.2'")
	require.Contains(t, msg, "Build info: version: '4.45.0', revision: 'cd6a3cdfca'")

	// no binary: the slot's own Chrome "crashed"
	_, _, body = split(t, Respond("POST", "/session", []byte(`{"capabilities":{"alwaysMatch":{"browserName":"chrome"}}}`)))
	require.Contains(t, gridValue(t, body)["message"], "chrome location /usr/bin/google-chrome is no longer running")

	// a browser the Chrome-only node does not offer
	_, _, body = split(t, Respond("POST", "/session", []byte(`{"capabilities":{"alwaysMatch":{"browserName":"firefox"}}}`)))
	require.Equal(t, "session not created", gridValue(t, body)["error"])
	require.Contains(t, gridValue(t, body)["message"], "browserName firefox")

	status, _, body = split(t, Respond("POST", "/session", []byte("{")))
	require.Equal(t, "HTTP/1.1 400 Bad Request", status)
	require.Equal(t, "invalid argument", gridValue(t, body)["error"])
}

func TestEchoIsBounded(t *testing.T) {
	long := `{"capabilities":{"alwaysMatch":{"goog:chromeOptions":{"binary":"/` + strings.Repeat("p", 900) + `"}}}}`
	_, _, body := split(t, Respond("POST", "/session", []byte(long)))
	msg := gridValue(t, body)["message"].(string)
	require.Contains(t, msg, "/"+strings.Repeat("p", maxEchoLength-1)+" is no longer running")
	require.NotContains(t, msg, strings.Repeat("p", maxEchoLength))
}

func TestInvalidSessionAndUnknownCommand(t *testing.T) {
	status, _, body := split(t, Respond("DELETE", "/session/0123abcd/window", nil))
	require.Equal(t, "HTTP/1.1 404 Not Found", status)
	v := gridValue(t, body)
	require.Equal(t, "invalid session id", v["error"])
	require.Contains(t, v["message"], "Unable to find session with ID: 0123abcd")

	// IDs that are not hex are not reflected
	_, _, body = split(t, Respond("GET", "/session/<script>/url", nil))
	require.NotContains(t, gridValue(t, body)["message"], "script")

	status, _, body = split(t, Respond("GET", "/actuator/env", nil))
	require.Equal(t, "HTTP/1.1 404 Not Found", status)
	v = gridValue(t, body)
	require.Equal(t, "unknown command", v["error"])
	require.Equal(t, "Unable to find handler for (GET) /actuator/env", v["message"])

	// GET /session is not new-session
	_, _, body = split(t, Respond("GET", "/session", nil))
	require.Equal(t, "unknown command", gridValue(t, body)["error"])
}

func TestGraphQL(t *testing.T) {
	fixedGrid(t)
	q := `{"query":"{ grid { uri, totalSlots, nodeCount, sessionCount, version } }"}`
	status, _, body := split(t, Respond("POST", "/graphql", []byte(q)))
	require.Equal(t, "HTTP/1.1 200 OK", status)
	var v struct {
		Data struct {
			Grid map[string]any `json:"grid"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &v))
	require.Equal(t, map[string]any{
		"uri": "http://172.17.0.2:4444", "totalSlots": 1.0, "nodeCount": 1.0, "sessionCount": 0.0, "version": "4.45.0",
	}, v.Data.Grid)

	_, _, body = split(t, Respond("POST", "/graphql", []byte(`{"query":"{ sessionsInfo { sessions { id } } }"}`)))
	require.Contains(t, string(body), `"errors"`)
}
