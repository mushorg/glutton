package tcp

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestMemcacheVerb(t *testing.T) {
	require.Equal(t, "stats", memcacheVerb("stats\r\n"))
	require.Equal(t, "stats", memcacheVerb("STATS\r\n"))
	require.Equal(t, "get", memcacheVerb("get foo\r\n"))
	require.Equal(t, "set", memcacheVerb("set k 0 0 3\r\n"))
	require.Equal(t, "", memcacheVerb("\r\n"))
}

func TestHandleMemcacheStats(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- handleMemcache(context.Background(), newMemcacheServer(serverConn), connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte("stats\r\n"))
	require.NoError(t, err)

	reader := bufio.NewReader(client)
	var resp []byte
	for {
		line, err := reader.ReadBytes('\n')
		require.NoError(t, err)
		resp = append(resp, line...)
		if string(line) == "END\r\n" {
			break
		}
	}
	require.Equal(t, string(memcacheStatsResponse()), string(resp))
	require.Contains(t, string(resp), "STAT version 1.6.22\r\n")

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "memcache", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedMemcache)
	require.True(t, ok, "decoded should be []parsedMemcache")
	require.Equal(t, []parsedMemcache{
		{Direction: "read", Command: "stats", Payload: []byte("stats\r\n")},
		{Direction: "write", Payload: memcacheStatsResponse()},
	}, events)
}

func TestHandleMemcacheSetGet(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- handleMemcache(context.Background(), newMemcacheServer(serverConn), connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte("set foo 0 0 3\r\nbar\r\n"))
	require.NoError(t, err)

	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "STORED\r\n", line)

	_, err = client.Write([]byte("get foo\r\n"))
	require.NoError(t, err)

	var getResp []byte
	for {
		line, err := reader.ReadBytes('\n')
		require.NoError(t, err)
		getResp = append(getResp, line...)
		if string(line) == "END\r\n" {
			break
		}
	}
	require.Equal(t, "VALUE foo 0 3\r\nbar\r\nEND\r\n", string(getResp))

	_, err = client.Write([]byte("quit\r\n"))
	require.NoError(t, err)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "memcache", produced.protocol)
	events, ok := produced.decoded.([]parsedMemcache)
	require.True(t, ok)

	require.Equal(t, []parsedMemcache{
		{Direction: "read", Command: "set", Payload: []byte("set foo 0 0 3\r\nbar\r\n")},
		{Direction: "write", Payload: []byte("STORED\r\n")},
		{Direction: "read", Command: "get", Payload: []byte("get foo\r\n")},
		{Direction: "write", Payload: []byte("VALUE foo 0 3\r\nbar\r\nEND\r\n")},
		{Direction: "read", Command: "quit", Payload: []byte("quit\r\n")},
	}, events)
}

func TestHandleMemcacheEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()

	done := make(chan error, 1)
	go func() {
		done <- handleMemcache(context.Background(), newMemcacheServer(serverConn), connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	select {
	case extra := <-hp.produced:
		t.Fatalf("connect-only probe should not produce an event, got: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleMemcacheStatsOnlyPayloadNoPadding(t *testing.T) {
	// Regression: the old handler produced the full 1024-byte read buffer
	// (NUL-padded). The first event payload must be exactly the command line.
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMemcache(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte("stats\r\n"))
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, io.LimitReader(client, int64(len(memcacheStatsResponse()))))
	require.NoError(t, err)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedMemcache)
	require.Equal(t, []byte("stats\r\n"), events[0].Payload)
	require.Len(t, events[0].Payload, 7)
}

func TestHandleMemcacheClientClosesAfterStats(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- handleMemcache(context.Background(), newMemcacheServer(serverConn), connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte("stats\r\n"))
	require.NoError(t, err)
	require.NoError(t, client.Close()) // scanner-style: do not read the STAT response
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedMemcache)
	require.True(t, ok)
	require.NotEmpty(t, events, "expected at least the stats read frame")
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "stats", events[0].Command)
	require.Equal(t, []byte("stats\r\n"), events[0].Payload)
}

func TestHandleMemcachePartialLineOnEOF(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- handleMemcache(context.Background(), newMemcacheServer(serverConn), connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte("stats")) // no newline
	require.NoError(t, err)
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedMemcache)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 1)
	require.Equal(t, "stats", events[0].Command)
	require.Equal(t, []byte("stats"), events[0].Payload)
}
