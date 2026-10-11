package tcp

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func runIdent(t *testing.T, send func(c net.Conn)) (producedTCP, []byte) {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleIdent(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	send(client)
	resp, _ := io.ReadAll(client)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	return produced, resp
}

// Captured: Ochi event 231284cf-a634-469d-95c0-a70e859aabad (tcp/113).
var identQuery = []byte("\x36\x31\x39\x31\x2c\x20\x32\x33\x0a") // "6191, 23\n"

func TestHandleIdentQuery(t *testing.T) {
	const reply = "6191, 23 : ERROR : NO-USER\r\n"
	produced, resp := runIdent(t, func(c net.Conn) {
		_, err := c.Write(identQuery)
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, reply, line)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, "ident", produced.protocol)
	require.Equal(t, identQuery, produced.payload)
	require.Equal(t, []parsedIdent{
		{Direction: "read", Command: "query", ServerPort: 6191, ClientPort: 23, Payload: identQuery},
		{Direction: "write", Status: "no-user", Payload: []byte(reply)},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleIdentMultipleQueries(t *testing.T) {
	produced, _ := runIdent(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		for i := 0; i < maxIdentQueries; i++ {
			_, err := c.Write([]byte("0 , 80\r\n"))
			require.NoError(t, err)
			line, err := r.ReadString('\n')
			require.NoError(t, err)
			require.Equal(t, "0, 80 : ERROR : INVALID-PORT\r\n", line)
		}
	})
	events := produced.decoded.([]parsedIdent)
	require.Len(t, events, 2*maxIdentQueries)
	require.Equal(t, "invalid-port", events[1].Status)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}

func TestHandleIdentNotIdent(t *testing.T) {
	produced, resp := runIdent(t, func(c net.Conn) {
		_, err := c.Write([]byte("GET / HTTP/1.0\r\n"))
		require.NoError(t, err)
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedIdent{
		{Direction: "read", Payload: []byte("GET / HTTP/1.0\r\n")},
	}, produced.decoded)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleIdentEarlyDisconnect(t *testing.T) {
	produced, resp := runIdent(t, func(c net.Conn) {
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, "ident", produced.protocol)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleIdentNoNewline(t *testing.T) {
	produced, _ := runIdent(t, func(c net.Conn) {
		_, err := c.Write([]byte("6191, 23"))
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	// net.Pipe is synchronous, so the reply fails once the client closed.
	events := produced.decoded.([]parsedIdent)
	require.NotEmpty(t, events)
	require.Equal(t, parsedIdent{Direction: "read", Command: "query", ServerPort: 6191, ClientPort: 23, Payload: []byte("6191, 23")}, events[0])
}

func TestHandleIdentOversize(t *testing.T) {
	produced, resp := runIdent(t, func(c net.Conn) {
		// net.Pipe blocks until the peer reads, so send the surplus off-thread.
		go func() { _, _ = c.Write([]byte(strings.Repeat("1", 1024))) }()
	})
	require.Empty(t, resp)
	events := produced.decoded.([]parsedIdent)
	require.Len(t, events, 1)
	require.Len(t, events[0].Payload, 128)
	require.True(t, events[0].Truncated)
}
