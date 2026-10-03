package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
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
	require.Equal(t, reply[:n], events[1].Payload)
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
