package tcp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func runWhois(t *testing.T, send func(c net.Conn)) (producedTCP, []byte) {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleWHOIS(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
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

func TestHandleWHOISQuery(t *testing.T) {
	produced, resp := runWhois(t, func(c net.Conn) {
		_, err := c.Write([]byte("example.com\r\n"))
		require.NoError(t, err)
	})
	require.Equal(t, whoisNoMatch, string(resp))
	require.Equal(t, "whois", produced.protocol)
	require.Equal(t, []parsedWhois{
		{Direction: "read", Command: "example.com", Payload: []byte("example.com\r\n")},
		{Direction: "write", Status: "no-match", Payload: []byte(whoisNoMatch)},
	}, produced.decoded)
}

func TestHandleWHOISNoNewline(t *testing.T) {
	produced, _ := runWhois(t, func(c net.Conn) {
		_, err := c.Write([]byte("1.2.3.4"))
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	// net.Pipe is synchronous, so the reply may fail once the client closed.
	events := produced.decoded.([]parsedWhois)
	require.NotEmpty(t, events)
	require.Equal(t, "1.2.3.4", events[0].Command)
}

func TestHandleWHOISEarlyDisconnect(t *testing.T) {
	produced, resp := runWhois(t, func(c net.Conn) {
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, "whois", produced.protocol)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleWHOISOversize(t *testing.T) {
	produced, _ := runWhois(t, func(c net.Conn) {
		// net.Pipe blocks until the peer reads, so send the surplus off-thread.
		go func() { _, _ = c.Write([]byte(strings.Repeat("A", maxWhoisQuery*2))) }()
	})
	events := produced.decoded.([]parsedWhois)
	require.Len(t, events, 2)
	require.Len(t, events[0].Payload, maxWhoisQuery)
	require.True(t, events[0].Truncated)
}
