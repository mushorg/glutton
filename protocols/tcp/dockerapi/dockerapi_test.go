package dockerapi

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 11, 8, 11, 42, 22, 0, time.UTC)

func parse(t *testing.T, raw []byte, method string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: method})
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func TestIsPort(t *testing.T) {
	require.True(t, IsPort(2375))
	require.True(t, IsPort(2376))
	require.False(t, IsPort(2377))
}

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{
		"/_ping":                 "/_ping",
		"/v1.41/_ping":           "/_ping",
		"/v1.16/version":         "/version",
		"/version/":              "/version",
		"/v1.24/containers/json": "/containers/json",
		"/v1.41":                 "/",
		"/":                      "/",
		"/vx/version":            "/vx/version",
	} {
		require.Equal(t, want, Route(in), in)
	}
}

func TestRespondPing(t *testing.T) {
	resp, body := parse(t, Respond(http.MethodGet, "/_ping", nil, testNow), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "OK", string(body))
	require.Equal(t, "1.41", resp.Header.Get("Api-Version"))
	require.Equal(t, "false", resp.Header.Get("Docker-Experimental"))
	require.Equal(t, "linux", resp.Header.Get("Ostype"))
	require.Equal(t, "2", resp.Header.Get("Builder-Version"))
	require.Equal(t, "Docker/20.10.9 (linux)", resp.Header.Get("Server"))
	require.Equal(t, "Sun, 08 Nov 2026 11:42:22 GMT", resp.Header.Get("Date"))
}

func TestRespondPingHead(t *testing.T) {
	raw := Respond(http.MethodHead, "/_ping", nil, testNow)
	require.True(t, bytes.HasSuffix(raw, []byte("Content-Length: 2\r\n\r\n")))
}

func TestRespondVersion(t *testing.T) {
	version := []byte(`{"ApiVersion":"1.41"}`)
	resp, body := parse(t, Respond(http.MethodGet, "/v1.24/version", version, testNow), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	require.Equal(t, "{\"ApiVersion\":\"1.41\"}\n", string(body))
	require.Equal(t, `{"ApiVersion":"1.41"}`, string(version), "caller's slice must not be modified")
}

func TestRespondLists(t *testing.T) {
	for _, path := range []string{"/containers/json", "/v1.41/images/json"} {
		resp, body := parse(t, Respond(http.MethodGet, path, nil, testNow), http.MethodGet)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Equal(t, "[]\n", string(body), path)
	}
}

func TestRespondNotFound(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/containers/create"},
		{http.MethodGet, "/"},
		{http.MethodPost, "/_ping"},
	} {
		resp, body := parse(t, Respond(c.method, c.path, nil, testNow), c.method)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, c.path)
		require.Equal(t, "{\"message\":\"page not found\"}\n", string(body), c.path)
	}
}
