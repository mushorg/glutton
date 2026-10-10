package protocols

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type catchAllProduced struct {
	protocol string
	md       connection.Metadata
	frames   []map[string]any
}

// catchAllHoneypot records each produced event's metadata and decoded frames.
type catchAllHoneypot struct {
	protocolHoneypot
	events chan catchAllProduced
}

func (h *catchAllHoneypot) ProduceTCP(protocol string, _ net.Conn, md connection.Metadata, _ []byte, decoded interface{}) error {
	ev := catchAllProduced{protocol: protocol, md: md}
	if raw, err := json.Marshal(decoded); err == nil {
		_ = json.Unmarshal(raw, &ev.frames)
	}
	h.events <- ev
	return nil
}

// dispatchCatchAll serves one loopback connection on port through the
// catch-all, lets client drive it, and returns the single produced event.
func dispatchCatchAll(t *testing.T, port uint16, client func(net.Conn)) catchAllProduced {
	t.Helper()
	t.Chdir(t.TempDir()) // HandleTCP stores payloads in ./payloads
	prevMax := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	prevTimeout := viper.GetInt("conn_timeout")
	viper.Set("conn_timeout", 1) // HTTP sessions produce once idle this long
	prevSpicy := viper.GetBool("spicy.enabled")
	viper.Set("spicy.enabled", false)
	t.Cleanup(func() {
		viper.Set("max_tcp_payload", prevMax)
		viper.Set("conn_timeout", prevTimeout)
		viper.Set("spicy.enabled", prevSpicy)
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &catchAllHoneypot{events: make(chan catchAllProduced, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["tcp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: port})
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	client(conn)
	require.NoError(t, conn.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	var ev catchAllProduced
	select {
	case ev = <-hp.events:
	case <-time.After(5 * time.Second):
		t.Fatal("no event produced")
	}
	select {
	case extra := <-hp.events:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
	return ev
}

func tlsClient(t *testing.T, c net.Conn) *tls.Conn {
	t.Helper()
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test client for a self-signed cert
	require.NoError(t, tc.Handshake())
	return tc
}

// The zgrab request from Ochi event 6d9554bb-28d4-41f1-b4ec-fdc9cc4ea56f,
// sent inside TLS to tcp/8091; older sensors answered it with random bytes.
const zgrabVersions = "GET /versions HTTP/1.1\r\nHost: 1.2.3.4:8091\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"

func TestCatchAllTLSHTTPGoesToHTTPHandler(t *testing.T) {
	ev := dispatchCatchAll(t, 8091, func(c net.Conn) {
		tc := tlsClient(t, c)
		_, err := io.WriteString(tc, zgrabVersions)
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})
	require.Equal(t, "http", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, "TLS 1.3", ev.md.TLS.Version)
	require.NotEmpty(t, ev.md.TLS.Cipher)
	require.NotEmpty(t, ev.md.TLS.JA4)
	require.NotEmpty(t, ev.frames)
	require.Equal(t, "read", ev.frames[0]["direction"])
	require.Equal(t, "/versions", ev.frames[0]["path"])
}

func TestCatchAllPlainHTTPWithoutSpicy(t *testing.T) {
	ev := dispatchCatchAll(t, 9999, func(c net.Conn) {
		_, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: 192.0.2.1:9999\r\n\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})
	require.Equal(t, "http", ev.protocol)
	require.Nil(t, ev.md.TLS)
}

func TestCatchAllTLSNonHTTPStaysTCP(t *testing.T) {
	payload := []byte("\x10\x20\x30\x40 not a known protocol\r\n")
	ev := dispatchCatchAll(t, 9999, func(c net.Conn) {
		tc := tlsClient(t, c)
		_, err := tc.Write(payload)
		require.NoError(t, err)
		reply := make([]byte, 4096)
		n, err := tc.Read(reply)
		require.NoError(t, err)
		require.NotZero(t, n)
	})
	require.Equal(t, "tcp", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Len(t, ev.frames, 3)
	require.Equal(t, "tls-clienthello", ev.frames[0]["command"])
	require.Equal(t, "read", ev.frames[1]["direction"])
	require.Equal(t, "write", ev.frames[2]["direction"])
	require.Equal(t, "random", ev.frames[2]["status"])
}

func TestCatchAllTLSHandshakeOnly(t *testing.T) {
	ev := dispatchCatchAll(t, 8091, func(c net.Conn) {
		tlsClient(t, c)
	})
	require.Equal(t, "tcp", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, connection.EndClientClose, ev.md.EndReason)
	require.Len(t, ev.frames, 1)
	require.Equal(t, "tls-clienthello", ev.frames[0]["command"])
}

func TestCatchAllUppercaseNonHTTPStaysTCP(t *testing.T) {
	// starts like "HEAD " but is not a request line
	ev := dispatchCatchAll(t, 9999, func(c net.Conn) {
		_, err := io.WriteString(c, "HELP\r\n")
		require.NoError(t, err)
		reply := make([]byte, 4096)
		n, err := c.Read(reply)
		require.NoError(t, err)
		require.NotZero(t, n)
	})
	require.Equal(t, "tcp", ev.protocol)
	require.Equal(t, "HELP\r\n", payloadOf(t, ev.frames[0]))
}

func payloadOf(t *testing.T, frame map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(frame["payload"])
	require.NoError(t, err)
	var b []byte
	require.NoError(t, json.Unmarshal(raw, &b))
	return string(b)
}

func TestLooksLikeHTTPRequest(t *testing.T) {
	for _, tc := range []struct {
		in    string
		start bool
		full  bool
	}{
		{"GET / HTTP/1.1", true, true},
		{"PROPFIND /x", true, true},
		{"OPTIONS * HTTP/1.1", true, true},
		{"POS", true, false},
		{"POSTX", true, false},
		{"HELP\r\n", false, false},
		{"PRI * HTTP/2.0", false, false},
		{"\x16\x03\x01", false, false},
		{"get / http/1.1", false, false},
	} {
		require.Equal(t, tc.start, looksLikeHTTPMethodStart([]byte(tc.in)[:min(len(tc.in), 4)]), tc.in)
		require.Equal(t, tc.full, looksLikeHTTPRequest([]byte(tc.in)), tc.in)
	}
}
