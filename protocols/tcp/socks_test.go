package tcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/socks"
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
	judge := socks.TunnelHTTPReply()
	require.Equal(t, judge, socksExchange(t, client, socksTunnelGET, len(judge)))

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{
		{Direction: "read", Command: "socks4a-connect", Path: "httpbin.org:80", Version: 4, Host: "httpbin.org", Port: 80, Payload: socks4aHttpbin},
		{Direction: "write", Command: "socks4a-connect", Status: "granted", Payload: granted},
		{Direction: "read", Command: "tunnel", Path: "httpbin.org:80", Payload: socksTunnelGET, PayloadHash: helpers.SHA256Hex(socksTunnelGET)},
		{Direction: "write", Command: "tunnel", Status: "200", Payload: judge},
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
	judge := socks.TunnelHTTPReply()
	require.Equal(t, judge, socksExchange(t, client, socksTunnelGET, len(judge)))

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{
		{Direction: "read", Command: "socks5-greeting", Version: 5, Methods: []int{0}, Payload: []byte{0x05, 0x01, 0x00}},
		{Direction: "write", Command: "socks5-greeting", Status: "no-auth", Payload: []byte{0x05, 0x00}},
		{Direction: "read", Command: "socks5-connect", Path: "httpbin.org:80", Version: 5, Host: "httpbin.org", Port: 80, Payload: connect},
		{Direction: "write", Command: "socks5-connect", Status: "granted", Payload: granted},
		{Direction: "read", Command: "tunnel", Path: "httpbin.org:80", Payload: socksTunnelGET, PayloadHash: helpers.SHA256Hex(socksTunnelGET)},
		{Direction: "write", Command: "tunnel", Status: "200", Payload: judge},
	}, frames)
}

// Ochi 2dfb646d-c67a-4073-90bf-a7a1d80bd953: SOCKS5 CONNECT api.ipinfo.io:443
// then a TLS ClientHello (PFCLOUD open-proxy judge).
var socks5IpinfoConnect = []byte("\x05\x01\x00\x03\rapi.ipinfo.io\x01\xbb")

// Ochi 6c15697e-3ba8-4453-b035-57aa7eb10e9a: SOCKS5 CONNECT ipv4.icanhazip.com:443
// (PFCLOUD open-proxy judge; older sensors served CN=localhost and the client
// aborted during the handshake).
var socks5IcanhazConnect = []byte("\x05\x01\x00\x03\x12ipv4.icanhazip.com\x01\xbb")

func TestTunnelCertName(t *testing.T) {
	require.Equal(t, "ipv4.icanhazip.com", tunnelCertName("ipv4.icanhazip.com", "other.example:443"))
	require.Equal(t, "api.ipinfo.io", tunnelCertName("", "api.ipinfo.io:443"))
	require.Equal(t, "", tunnelCertName("", "not-a-host-port"))
}

// tlsJudgeClient accepts the honeypot's self-signed cert but still checks that
// the leaf name matches serverName (the check open-proxy judges often do).
func tlsJudgeClient(conn net.Conn, serverName string) *tls.Conn {
	return tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return state.PeerCertificates[0].VerifyHostname(serverName)
		},
	})
}

func TestHandleSOCKS5TLSJudge(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	require.Equal(t, []byte{0x05, 0x00}, socksExchange(t, client, []byte{0x05, 0x01, 0x00}, 2))
	granted := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x9c, 0x40}
	require.Equal(t, granted, socksExchange(t, client, socks5IpinfoConnect, 10))

	tc := tlsJudgeClient(client, "api.ipinfo.io")
	require.NoError(t, tc.Handshake())
	require.NoError(t, tc.ConnectionState().PeerCertificates[0].VerifyHostname("api.ipinfo.io"))
	req := []byte("GET / HTTP/1.1\r\nHost: api.ipinfo.io\r\n\r\n")
	_, err := tc.Write(req)
	require.NoError(t, err)
	judge := socks.TunnelHTTPReply()
	got := make([]byte, len(judge))
	_, err = io.ReadFull(tc, got)
	require.NoError(t, err)
	require.Equal(t, judge, got)
	_ = client.Close() // server already closed after the judge reply

	require.NoError(t, <-done)
	var ev producedTCP
	select {
	case ev = <-hp.produced:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced SOCKS event")
	}
	require.Equal(t, "socks", ev.protocol)
	frames, ok := ev.decoded.([]parsedSOCKS)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(frames), 7)
	require.Equal(t, "socks5-connect", frames[2].Command)
	require.Equal(t, "api.ipinfo.io:443", frames[2].Path)
	require.Equal(t, "granted", frames[3].Status)
	require.Equal(t, "tls-clienthello", frames[4].Command)
	require.Equal(t, "api.ipinfo.io", frames[4].SNI)
	require.NotEmpty(t, frames[4].JA4)
	require.Equal(t, "tls-handshake", frames[5].Status)
	require.NotEmpty(t, frames[5].Payload)
	require.Equal(t, "tunnel", frames[6].Command)
	require.Equal(t, req, frames[6].Payload)
	require.Equal(t, "200", frames[7].Status)
	require.Equal(t, judge, frames[7].Payload)
	require.NotNil(t, ev.tls)
	require.Equal(t, "api.ipinfo.io", ev.tls.ServerName)
}

func TestHandleSOCKS5TLSJudgeIcanhazip(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	require.Equal(t, []byte{0x05, 0x00}, socksExchange(t, client, []byte{0x05, 0x01, 0x00}, 2))
	granted := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x9c, 0x40}
	require.Equal(t, granted, socksExchange(t, client, socks5IcanhazConnect, 10))

	tc := tlsJudgeClient(client, "ipv4.icanhazip.com")
	require.NoError(t, tc.Handshake())
	req := []byte("GET / HTTP/1.1\r\nHost: ipv4.icanhazip.com\r\n\r\n")
	_, err := tc.Write(req)
	require.NoError(t, err)
	judge := socks.TunnelHTTPReply()
	got := make([]byte, len(judge))
	_, err = io.ReadFull(tc, got)
	require.NoError(t, err)
	require.Equal(t, judge, got)
	_ = client.Close()

	require.NoError(t, <-done)
	var ev producedTCP
	select {
	case ev = <-hp.produced:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced SOCKS event")
	}
	frames, ok := ev.decoded.([]parsedSOCKS)
	require.True(t, ok)
	require.Equal(t, "ipv4.icanhazip.com:443", frames[2].Path)
	require.Equal(t, "ipv4.icanhazip.com", frames[4].SNI)
	require.Equal(t, "200", frames[7].Status)
	require.NotNil(t, ev.tls)
	require.Equal(t, "ipv4.icanhazip.com", ev.tls.ServerName)
}

func TestHandleSOCKS5UserPassRecordsPassword(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	require.Equal(t, []byte{0x05, 0x02}, socksExchange(t, client, []byte{0x05, 0x02, 0x00, 0x02}, 2))
	require.Equal(t, []byte{0x01, 0x00}, socksExchange(t, client, []byte("\x01\x05admin\x0asecret-pw!"), 2))
	connect := []byte("\x05\x01\x00\x01\xc0\x00\x02\x01\x01\xbb")
	socksExchange(t, client, connect, 10)

	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 6)
	require.Equal(t, parsedSOCKS{Direction: "read", Command: "socks5-auth", Version: 5, User: "admin", Password: "secret-pw!", Payload: []byte("\x01\x05admin\x0asecret-pw!")}, frames[2])
	require.Equal(t, "granted", frames[3].Status)
	require.Equal(t, "192.0.2.1:443", frames[4].Path)
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

// Ochi b53eecbe-20f7-4fdc-84ea-0a530f6f9833: SOCKS4a CONNECT, no hostname.
var socks4aNoHost = []byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00")

func TestHandleSOCKS4aMissingHostGranted(t *testing.T) {
	prev := socksHostWait
	socksHostWait = 50 * time.Millisecond
	t.Cleanup(func() { socksHostWait = prev })
	client, hp, done := startSOCKS(t, 4096)

	reply := socksExchange(t, client, socks4aNoHost, 8)
	granted := []byte{0x00, 0x5a, 0x9c, 0x40, 0, 0, 0, 0}
	require.Equal(t, granted, reply)

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, []parsedSOCKS{
		{Direction: "read", Command: "socks4a-connect", Path: ":80", Version: 4, Port: 80, Truncated: true, Payload: socks4aNoHost},
		{Direction: "write", Command: "socks4a-connect", Status: "granted", Payload: granted},
	}, frames)
}

func TestHandleSOCKS4aHostArrivesLater(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)

	_, err := client.Write(socks4aNoHost)
	require.NoError(t, err)
	_, err = client.Write([]byte("httpbin.org\x00"))
	require.NoError(t, err)
	reply := make([]byte, 8)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)

	frames := finishSOCKS(t, client, hp, done)
	require.Equal(t, "httpbin.org", frames[0].Host)
	require.False(t, frames[0].Truncated)
	require.Equal(t, "granted", frames[1].Status)
}

func TestHandleSOCKS4aMissingHostDisconnect(t *testing.T) {
	client, hp, done := startSOCKS(t, 4096)
	_, err := client.Write(socks4aNoHost)
	require.NoError(t, err)
	frames := finishSOCKS(t, client, hp, done)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
}
