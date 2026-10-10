package tcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/banners"
	"github.com/mushorg/glutton/protocols/tcp/rfb"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type staticAddr struct{ addr string }

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return a.addr }

type connWithRemote struct {
	net.Conn
	remote net.Addr
}

func (c connWithRemote) RemoteAddr() net.Addr { return c.remote }

func TestHandleTCPCapturesClientPacket(t *testing.T) {
	t.Chdir(t.TempDir())
	previousMaxPayload := viper.Get("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Cleanup(func() {
		viper.Set("max_tcp_payload", previousMaxPayload)
	})

	client, serverConn := net.Pipe()
	defer client.Close()
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	payload := []byte("GET / HTTP/1.0\r\n\r\n")

	done := make(chan error, 1)
	go func() {
		done <- HandleTCP(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(payload)
	require.NoError(t, err)

	reply := make([]byte, 1024)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.Greater(t, n, 0)

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "tcp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedTCP)
	require.True(t, ok, "decoded should be []parsedTCP")
	require.GreaterOrEqual(t, len(events), 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, payload, events[0].Payload)
	require.NotEmpty(t, events[0].PayloadHash)

	require.Len(t, events, 2)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "random", events[1].Status)
	require.Equal(t, reply[:n], events[1].Payload)
}

func startCatchAll(t *testing.T, port uint16) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	return startCatchAllWith(t, port, HandleTCP)
}

func startCatchAllWith(t *testing.T, port uint16, handler func(context.Context, net.Conn, connection.Metadata, interfaces.Logger, interfaces.Honeypot) error) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	t.Chdir(t.TempDir())
	previousMaxPayload := viper.Get("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Cleanup(func() { viper.Set("max_tcp_payload", previousMaxPayload) })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- handler(context.Background(), serverConn, connection.Metadata{TargetPort: port}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func finishCatchAll(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) []parsedTCP {
	t.Helper()
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	require.Equal(t, "tcp", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedTCP)
	require.True(t, ok)
	return events
}

func readAll(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	require.NoError(t, err)
	return buf
}

func TestHandleTCPServerFirstBanner(t *testing.T) {
	client, hp, done := startCatchAll(t, 22)

	// the banner arrives before the client sends anything
	want, _ := banners.ForPort(22)
	banner := readAll(t, client, len(want.Data))
	require.Equal(t, want.Data, banner)

	clientBanner := []byte("SSH-2.0-libssh_0.9.6\r\n")
	_, err := client.Write(clientBanner)
	require.NoError(t, err)
	// the client banner matches the SSH signature: banner again
	again := readAll(t, client, len(want.Data))
	require.Equal(t, want.Data, again)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 3)
	require.Equal(t, parsedTCP{Direction: "write", Status: "ssh", Payload: banner, PayloadHash: helpers.SHA256Hex(banner)}, events[0])
	require.Equal(t, "read", events[1].Direction)
	require.Equal(t, "ssh", events[1].Command)
	require.Equal(t, clientBanner, events[1].Payload)
	require.Equal(t, "ssh", events[2].Status)
}

func TestHandleTCPRFBFollowUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		want    []byte
	}{
		{"3.8", "RFB 003.008\n", []byte{2, 2, 1}},
		{"3.7", "RFB 003.007\n", []byte{2, 2, 1}},
		{"3.3", "RFB 003.003\n", []byte{0, 0, 0, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, hp, done := startCatchAll(t, 5900)

			banner := readAll(t, client, len(rfb.ServerVersion))
			require.Equal(t, rfb.ServerVersion, banner)
			_, err := client.Write([]byte(tc.version))
			require.NoError(t, err)
			// the security handshake follows instead of random bytes
			reply := readAll(t, client, len(tc.want))
			require.Equal(t, tc.want, reply)

			events := finishCatchAll(t, client, hp, done)
			require.Len(t, events, 3)
			require.Equal(t, parsedTCP{Direction: "write", Status: "rfb", Payload: banner, PayloadHash: helpers.SHA256Hex(banner)}, events[0])
			require.Equal(t, "read", events[1].Direction)
			require.Equal(t, "rfb", events[1].Command)
			require.Equal(t, []byte(tc.version), events[1].Payload)
			require.Equal(t, parsedTCP{Direction: "write", Status: "rfb-security", Payload: tc.want, PayloadHash: helpers.SHA256Hex(tc.want)}, events[2])
		})
	}
}

func TestHandleTCPRFBNonVersionGetsRandom(t *testing.T) {
	client, hp, done := startCatchAll(t, 5900)

	readAll(t, client, len(rfb.ServerVersion))
	_, err := client.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	require.NoError(t, err)
	// drain the whole reply: the pipe is synchronous and the handler closes after it
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(reply), 12)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 3)
	require.Empty(t, events[1].Command)
	require.Equal(t, parsedTCP{Direction: "write", Status: "random", Payload: reply, PayloadHash: helpers.SHA256Hex(reply)}, events[2])
}

func TestHandleTCPPortReply(t *testing.T) {
	client, hp, done := startCatchAll(t, 1433)

	prelogin := []byte{0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00}
	_, err := client.Write(prelogin)
	require.NoError(t, err)
	want, _ := banners.ForPort(1433)
	reply := readAll(t, client, len(want.Data))
	require.Equal(t, want.Data, reply)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Empty(t, events[0].Command)
	require.Equal(t, prelogin, events[0].Payload)
	require.Equal(t, "mssql-prelogin", events[1].Status)
}

func TestHandleTCPSignatureBeatsPort(t *testing.T) {
	// TLS on the AJP port gets a TLS alert, not the AJP response
	client, hp, done := startCatchAll(t, 8009)

	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}
	_, err := client.Write(hello)
	require.NoError(t, err)
	alert := readAll(t, client, 7)
	require.Equal(t, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}, alert)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 2)
	require.Equal(t, "tls-alert", events[0].Command)
	require.Equal(t, "tls-alert", events[1].Status)
}

func TestHandleTCPSilentGreetsIdlePort(t *testing.T) {
	client, hp, done := startCatchAllWith(t, 4444, HandleTCPSilent)

	// dispatch saw no client bytes: the prompt comes first
	want, _ := banners.ForPort(4444)
	banner := readAll(t, client, len(want.Data))
	require.Equal(t, want.Data, banner)

	cmd := []byte("whoami\r\n")
	_, err := client.Write(cmd)
	require.NoError(t, err)
	// not the prompt again: no follow-up is emulated yet
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	require.NotEqual(t, want.Data, reply)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 3)
	require.Equal(t, parsedTCP{Direction: "write", Status: "cmd-shell", Payload: banner, PayloadHash: helpers.SHA256Hex(banner)}, events[0])
	require.Equal(t, "read", events[1].Direction)
	require.Equal(t, cmd, events[1].Payload)
	require.Equal(t, "random", events[2].Status)
}

func TestHandleTCPIdlePortClientFirst(t *testing.T) {
	// a client that spoke during the wait gets the prompt as the reply
	client, hp, done := startCatchAll(t, 4444)

	cmd := []byte("whoami\r\n")
	_, err := client.Write(cmd)
	require.NoError(t, err)
	want, _ := banners.ForPort(4444)
	reply := readAll(t, client, len(want.Data))
	require.Equal(t, want.Data, reply)

	events := finishCatchAll(t, client, hp, done)
	require.Len(t, events, 2)
	require.Equal(t, cmd, events[0].Payload)
	require.Equal(t, "cmd-shell", events[1].Status)
}

func TestHandleTCPSilentWithoutIdleBanner(t *testing.T) {
	client, hp, done := startCatchAllWith(t, 9999, HandleTCPSilent)
	events := finishCatchAll(t, client, hp, done)
	require.Empty(t, events)
}

func TestGreetsWhenIdle(t *testing.T) {
	require.True(t, GreetsWhenIdle(4444))
	require.False(t, GreetsWhenIdle(22), "server-first, not idle-greet")
	require.False(t, GreetsWhenIdle(80))
	require.False(t, GreetsWhenIdle(9999))
	require.False(t, HasServerBanner(4444))
}

func TestHandleTCPSilentClientNoReply(t *testing.T) {
	client, hp, done := startCatchAll(t, 9999)
	events := finishCatchAll(t, client, hp, done)
	require.Empty(t, events)
}

func TestHandleTCPEarlyDisconnectStillProduces(t *testing.T) {
	t.Chdir(t.TempDir())

	client, serverConn := net.Pipe()
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleTCP(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "tcp", produced.protocol)
	events, ok := produced.decoded.([]parsedTCP)
	require.True(t, ok, "decoded should be []parsedTCP")
	for _, event := range events {
		require.NotEqual(t, "read", event.Direction)
	}
}
