package tcp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/socks"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// Ochi event 137b2e1d-350c-4e23-bbb6-54a7f0ce35ef (tcp/30105): connect-back
// open-proxy check. CONNECT to the client's own address with proxy
// credentials root:123, then a random token through the tunnel.
var (
	httpConnectSelf  = []byte("CONNECT 93.152.221.108:80 HTTP/1.0\r\nHost: 93.152.221.108:80\r\nProxy-Authorization: Basic cm9vdDoxMjM=\r\n\r\n")
	httpConnectToken = []byte("83YgZ9EToNwBsC918xpPV1F78GqwqhpRsbMYjOtxCKle5cj8vS")
)

func startHTTPConnect(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	withHTTPSessionIdle(t, 50*time.Millisecond)
	prevMax := viper.Get("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Chdir(t.TempDir()) // helpers.Store writes ./payloads
	t.Cleanup(func() { viper.Set("max_tcp_payload", prevMax) })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{TargetPort: 30105}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// connectThrough sends req and reads the proxy's CONNECT reply.
func connectThrough(t *testing.T, client net.Conn, req []byte) {
	t.Helper()
	_, err := client.Write(req)
	require.NoError(t, err)
	got := make([]byte, len(httpConnectReply))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, httpConnectReply, got)
}

func finishHTTPConnect(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedHTTP) {
	t.Helper()
	_ = client.Close()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	ev := waitProduced(t, hp)
	require.Equal(t, "http", ev.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	frames, ok := ev.decoded.([]parsedHTTP)
	require.True(t, ok)
	return ev, frames
}

// requireConnectFrames checks the CONNECT read and the proxy's reply.
func requireConnectFrames(t *testing.T, frames []parsedHTTP, req []byte, target, user, pass string) {
	t.Helper()
	require.GreaterOrEqual(t, len(frames), 2)
	require.Equal(t, "read", frames[0].Direction)
	require.Equal(t, "CONNECT", frames[0].Command)
	require.Equal(t, target, frames[0].Path)
	require.Equal(t, target, frames[0].Host)
	require.Equal(t, user, frames[0].Username)
	require.Equal(t, pass, frames[0].Password)
	require.Equal(t, req, frames[0].Payload)
	require.NotEmpty(t, frames[0].SessionID)
	require.Equal(t, parsedHTTP{Direction: "write", Status: "200", SessionID: frames[0].SessionID, Payload: httpConnectReply}, frames[1])
}

func TestHandleHTTPConnectOpaqueTunnel(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	connectThrough(t, client, httpConnectSelf)
	_, err := client.Write(httpConnectToken)
	require.NoError(t, err)
	// opaque data gets no reply; the proxy hangs up
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	ev, frames := finishHTTPConnect(t, client, hp, done)
	require.Equal(t, httpConnectSelf, ev.payload)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Len(t, frames, 3)
	requireConnectFrames(t, frames, httpConnectSelf, "93.152.221.108:80", "root", "123")
	require.Equal(t, parsedHTTP{
		Direction:   "read",
		Command:     "tunnel",
		Path:        "93.152.221.108:80",
		SessionID:   frames[0].SessionID,
		Payload:     httpConnectToken,
		PayloadHash: helpers.SHA256Hex(httpConnectToken),
	}, frames[2])
	require.FileExists(t, filepath.Join("payloads", helpers.SHA256Hex(httpConnectToken)))
}

func TestHandleHTTPConnectTunnelPayloadsOff(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	prev := viper.Get("storage.tunnel_payloads")
	viper.Set("storage.tunnel_payloads", false)
	t.Cleanup(func() { viper.Set("storage.tunnel_payloads", prev) })
	connectThrough(t, client, httpConnectSelf)
	_, err := client.Write(httpConnectToken)
	require.NoError(t, err)
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	_, frames := finishHTTPConnect(t, client, hp, done)
	require.Len(t, frames, 3)
	// the event keeps the bytes and their hash; nothing is written to disk
	require.Equal(t, httpConnectToken, frames[2].Payload)
	require.Equal(t, helpers.SHA256Hex(httpConnectToken), frames[2].PayloadHash)
	require.NoDirExists(t, "payloads")
}

func TestHandleHTTPConnectJudge(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	connect := []byte("CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org:80\r\n\r\n")
	connectThrough(t, client, connect)
	judge := socks.TunnelHTTPReply()
	_, err := client.Write(socksTunnelGET)
	require.NoError(t, err)
	got := make([]byte, len(judge))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, judge, got)

	ev, frames := finishHTTPConnect(t, client, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Len(t, frames, 3)
	requireConnectFrames(t, frames, connect, "httpbin.org:80", "", "")
	tunnelHTTP := frames[2].HTTP
	requireJudgeHTTP(t, tunnelHTTP, judge)
	require.Equal(t, parsedHTTP{
		Direction:        "read",
		Command:          "tunnel",
		Path:             "httpbin.org:80",
		SessionID:        frames[0].SessionID,
		Payload:          socksTunnelGET,
		PayloadHash:      helpers.SHA256Hex(socksTunnelGET),
		Requests:         1,
		DistinctRequests: 1,
		RequestLine:      "GET /ip HTTP/1.1",
		HTTP:             tunnelHTTP,
	}, frames[2])
}

func TestHandleHTTPConnectTLSJudge(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	connectThrough(t, client, []byte("CONNECT api.ipinfo.io:443 HTTP/1.1\r\nHost: api.ipinfo.io:443\r\n\r\n"))

	tc := tlsJudgeClient(client, "api.ipinfo.io")
	require.NoError(t, tc.Handshake())
	_, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: api.ipinfo.io\r\n\r\n"))
	require.NoError(t, err)
	judge := socks.TunnelHTTPReply()
	got := make([]byte, len(judge))
	_, err = io.ReadFull(tc, got)
	require.NoError(t, err)
	require.Equal(t, judge, got)

	_, frames := finishHTTPConnect(t, client, hp, done)
	require.Len(t, frames, 5)
	require.Equal(t, "tls-clienthello", frames[2].Command)
	require.Equal(t, "api.ipinfo.io:443", frames[2].Path)
	require.NotNil(t, frames[2].ClientHello)
	require.Equal(t, "api.ipinfo.io", frames[2].SNI)
	require.Equal(t, "write", frames[3].Direction)
	require.Equal(t, "tls-handshake", frames[3].Status)
	require.NotEmpty(t, frames[3].Payload)
	require.Equal(t, "tunnel", frames[4].Command)
	requireJudgeHTTP(t, frames[4].HTTP, judge)
	// only the decrypted tunnel read is stored, never the ClientHello
	stored, err := os.ReadDir("payloads")
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, frames[4].PayloadHash, stored[0].Name())
}

func TestHandleHTTPConnectEarlyDisconnect(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	connectThrough(t, client, httpConnectSelf)

	ev, frames := finishHTTPConnect(t, client, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Len(t, frames, 2)
	requireConnectFrames(t, frames, httpConnectSelf, "93.152.221.108:80", "root", "123")
}

func TestHandleHTTPConnectTruncatedTunnel(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	viper.Set("max_tcp_payload", 16)
	connectThrough(t, client, httpConnectSelf)
	_, err := client.Write(httpConnectToken)
	require.NoError(t, err)

	_, frames := finishHTTPConnect(t, client, hp, done)
	require.Len(t, frames, 3)
	require.Equal(t, "tunnel", frames[2].Command)
	require.True(t, frames[2].Truncated)
	require.Equal(t, httpConnectToken[:16], frames[2].Payload)
}

func TestHandleHTTPProxyAuthorizationAbsoluteURI(t *testing.T) {
	client, hp, done := startHTTPConnect(t)
	req := []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n") // admin:admin
	_, err := client.Write(req)
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, sessionCookieFromHeaders(t, headers), "only CONNECT replies skip the session cookie")

	_, frames := finishHTTPConnect(t, client, hp, done)
	require.Equal(t, "GET", frames[0].Command)
	require.Equal(t, "admin", frames[0].Username)
	require.Equal(t, "admin", frames[0].Password)
}

func TestProxyBasicAuth(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(httpConnectSelf)))
	require.NoError(t, err)
	user, pass, ok := proxyBasicAuth(req)
	require.True(t, ok)
	require.Equal(t, "root", user)
	require.Equal(t, "123", pass)

	req.Header.Set("Proxy-Authorization", "Digest username=\"x\"")
	_, _, ok = proxyBasicAuth(req)
	require.False(t, ok)
}
