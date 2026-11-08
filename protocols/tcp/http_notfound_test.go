package tcp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestIsHTTPMissingPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/favicon.ico":                      true,
		"/FAVICON.ICO":                      true,
		"/sitemap_index.xml":                true,
		"/sitemap.xml":                      true,
		"/.well-known/security.txt":         true,
		"/.well-known/acme-challenge/abc":   true,
		"/apple-touch-icon.png":             true,
		"/apple-touch-icon-precomposed.png": true,
		"/":                                 false,
		"/robots.txt":                       false,
		"/ip":                               false,
		"/favicon.ico.php":                  false,
		"/.well-known":                      false,
		"/apple-touch-icon.php":             false,
	} {
		require.Equal(t, want, isHTTPMissingPath(path), path)
	}
}

func TestHTTPNotFoundContentLength(t *testing.T) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(httpNotFound("GET"))), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.Equal(t, httpNotFoundBody, string(body))
	require.Equal(t, strconv.Itoa(len(httpNotFoundBody)), resp.Header.Get("Content-Length"))
	require.Equal(t, httpNotFoundHead, string(httpNotFound("HEAD")))
}

func TestHandleHTTPMissingPath404(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err := client.Write(httpTestRequest("GET", "/favicon.ico", "", nil))
	require.NoError(t, err)
	status, headers, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, httpNotFoundBody, string(body))
	sessionID := sessionCookieFromHeaders(t, headers)

	// HEAD gets the same status and length, without a body
	_, err = client.Write(httpTestRequest("HEAD", "/.well-known/security.txt", sessionID, nil))
	require.NoError(t, err)
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodHead})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.Equal(t, int64(len(httpNotFoundBody)), resp.ContentLength)
	require.NoError(t, resp.Body.Close())

	// other paths keep the default empty 200
	_, err = client.Write(httpTestRequest("GET", "/", sessionID, nil))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, body)

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
	var got [][2]string
	for _, e := range events {
		if e.Direction == "read" {
			got = append(got, [2]string{e.Command, e.Path})
		} else {
			got = append(got, [2]string{"write", e.Status})
		}
	}
	require.Equal(t, [][2]string{
		{"GET", "/favicon.ico"}, {"write", "404"},
		{"HEAD", "/.well-known/security.txt"}, {"write", "404"},
		{"GET", "/"}, {"write", "200"},
	}, got)
}

// Captured shape (run-1794140965-1): an absolute-form GET for a sitemap
// through a proxy tunnel got the open-proxy judge JSON; it now gets a 404.
func TestHandleHTTPConnectMissingPath404(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	connect := []byte("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	connectThrough(t, client, connect)
	get := []byte("GET http://example.com/sitemap_index.xml HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	_, err := client.Write(get)
	require.NoError(t, err)
	want := httpNotFound("GET")
	got := make([]byte, len(want))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, want, got)

	_, frames := finishHTTPConnect(t, client, hp, done)
	require.Len(t, frames, 3)
	tunnelHTTP := frames[2].HTTP
	require.Len(t, tunnelHTTP, 2)
	require.Equal(t, "GET", tunnelHTTP[0].Command)
	require.Equal(t, "/sitemap_index.xml", tunnelHTTP[0].Path)
	require.Equal(t, "write", tunnelHTTP[1].Direction)
	require.Equal(t, "404", tunnelHTTP[1].Status)
	require.Equal(t, want, tunnelHTTP[1].Payload)
}
