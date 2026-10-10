package tcp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// SOCKS4a CONNECT httpbin.org:80 from Ochi event
// 2e27fe0b-5593-4090-bc5b-fddebc9666c6 (tcp/5678).
var socks4aHttpbin = []byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00httpbin.org\x00")

var socksTunnelGET = []byte("GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")

func startSOCKS(t *testing.T, maxPayload int) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	prevPort := socksBoundPort
	socksBoundPort = func() uint16 { return 40000 }
	prevMax := viper.Get("max_tcp_payload")
	viper.Set("max_tcp_payload", maxPayload)
	t.Chdir(t.TempDir()) // helpers.Store writes ./payloads
	t.Cleanup(func() {
		socksBoundPort = prevPort
		viper.Set("max_tcp_payload", prevMax)
	})

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleSOCKS(context.Background(), serverConn, connection.Metadata{TargetPort: 1080}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func socksExchange(t *testing.T, client net.Conn, req []byte, replyLen int) []byte {
	t.Helper()
	_, err := client.Write(req)
	require.NoError(t, err)
	reply := make([]byte, replyLen)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	return reply
}

func finishSOCKS(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) []parsedSOCKS {
	t.Helper()
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	var ev producedTCP
	select {
	case ev = <-hp.produced:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced SOCKS event")
	}
	require.Equal(t, "socks", ev.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	frames, ok := ev.decoded.([]parsedSOCKS)
	require.True(t, ok)
	return frames
}

func TestHandleSOCKS4aCapturedEvent(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	reply := socksExchange(t, client, socks4aHttpbin, 8)
	granted := []byte{0x00, 0x5a, 0x9c, 0x40, 0, 0, 0, 0}
	require.Equal(t, granted, reply)
	_, err := client.Write(socksTunnelGET)
	require.NoError(t, err)

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{
		{Direction: "read", Command: "socks4a-connect", Path: "httpbin.org:80", Version: 4, Host: "httpbin.org", Port: 80, Payload: socks4aHttpbin},
		{Direction: "write", Command: "socks4a-connect", Status: "granted", Payload: granted},
		{Direction: "read", Command: "tunnel", Path: "httpbin.org:80", Payload: socksTunnelGET, PayloadHash: helpers.SHA256Hex(socksTunnelGET)},
	}, frames)
}

func TestHandleSOCKS4BindRejected(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	req := []byte("\x04\x02\x01\xbb\xc0\x00\x02\x01scan\x00")
	reply := socksExchange(t, client, req, 8)
	require.Equal(t, []byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0}, reply)

	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 2)
	require.Equal(t, "socks4-bind", frames[0].Command)
	require.Equal(t, "scan", frames[0].User)
	require.Equal(t, "rejected", frames[1].Status)
}

func TestHandleSOCKS5NoAuth(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	require.Equal(t, []byte{0x05, 0x00}, socksExchange(t, client, []byte{0x05, 0x01, 0x00}, 2))
	connect := []byte("\x05\x01\x00\x03\x0bhttpbin.org\x00\x50")
	granted := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x9c, 0x40}
	require.Equal(t, granted, socksExchange(t, client, connect, 10))
	_, err := client.Write(socksTunnelGET)
	require.NoError(t, err)

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{
		{Direction: "read", Command: "socks5-greeting", Version: 5, Methods: []int{0}, Payload: []byte{0x05, 0x01, 0x00}},
		{Direction: "write", Command: "socks5-greeting", Status: "no-auth", Payload: []byte{0x05, 0x00}},
		{Direction: "read", Command: "socks5-connect", Path: "httpbin.org:80", Version: 5, Host: "httpbin.org", Port: 80, Payload: connect},
		{Direction: "write", Command: "socks5-connect", Status: "granted", Payload: granted},
		{Direction: "read", Command: "tunnel", Path: "httpbin.org:80", Payload: socksTunnelGET, PayloadHash: helpers.SHA256Hex(socksTunnelGET)},
	}, frames)
}

func TestHandleSOCKS5UserPassOmitsPassword(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	require.Equal(t, []byte{0x05, 0x02}, socksExchange(t, client, []byte{0x05, 0x02, 0x00, 0x02}, 2))
	require.Equal(t, []byte{0x01, 0x00}, socksExchange(t, client, []byte("\x01\x05admin\x0asecret-pw!"), 2))
	connect := []byte("\x05\x01\x00\x01\xc0\x00\x02\x01\x01\xbb")
	socksExchange(t, client, connect, 10)

	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 6)
	require.Equal(t, parsedSOCKS{Direction: "read", Command: "socks5-auth", Version: 5, User: "admin", Payload: []byte("\x01\x05admin\x0a**********")}, frames[2])
	require.Equal(t, "granted", frames[3].Status)
	require.Equal(t, "192.0.2.1:443", frames[4].Path)
	for _, f := range frames {
		require.NotContains(t, string(f.Payload), "secret-pw")
	}
}

func TestHandleSOCKS5NoAcceptableMethod(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	require.Equal(t, []byte{0x05, 0xff}, socksExchange(t, client, []byte{0x05, 0x01, 0x01}, 2))
	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 2)
	require.Equal(t, "no-acceptable-method", frames[1].Status)
}

func TestHandleSOCKS5UDPAssociateRejected(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	socksExchange(t, client, []byte{0x05, 0x01, 0x00}, 2)
	reply := socksExchange(t, client, []byte("\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"), 10)
	require.Equal(t, byte(0x07), reply[1])
	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, "socks5-udp-associate", frames[2].Command)
	require.Equal(t, "rejected", frames[3].Status)
}

func TestHandleSOCKSTunnelTruncated(t *testing.T) {
	client, hp, done := startSOCKS(t, 16)
	socksExchange(t, client, socks4aHttpbin, 8)
	_, err := client.Write(socksTunnelGET)
	require.NoError(t, err)

	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 3)
	require.True(t, frames[2].Truncated)
	require.Equal(t, socksTunnelGET[:16], frames[2].Payload)
}

func TestHandleSOCKSTruncatedRequest(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	_, err := client.Write([]byte{0x04, 0x01, 0x00})
	require.NoError(t, err)
	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{{Direction: "read", Version: 4, Payload: []byte{0x04, 0x01, 0x00}}}, frames)
}

func TestHandleSOCKSOversizeUserid(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	req := append([]byte("\x04\x01\x00\x50\x01\x02\x03\x04"), []byte(strings.Repeat("A", 300))...)
	// the handler gives up at the cap and closes, so the client write fails
	go func() { _, _ = client.Write(req) }()
	require.NoError(t, <-done)
	ev := <-hp.produced
	frames := ev.decoded.([]parsedSOCKS)
	require.Len(t, frames, 1)
	require.Len(t, frames[0].Payload, 8+256)
}

func TestHandleSOCKSGarbage(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	_, err := client.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	require.NoError(t, err)
	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{{Direction: "read", Payload: []byte("GET / HTTP/1.0\r\n\r\n")}}, frames)
}

func TestHandleSOCKSEarlyDisconnect(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	frames := finishSOCKS(t, client, hp, done)
	require.Empty(t, frames)
}
