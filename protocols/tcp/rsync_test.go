package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/rsync"
	"github.com/stretchr/testify/require"
)

// rsyncGreetingFixture is read frame 1 of the tcp/873 catch-all event from
// 134.185.88.23 (2026-10-24T17:46:57Z, payload SHA-256 dbc456a2…cfc6). The
// catch-all answered it with random bytes; the client sent it again and reset.
var rsyncGreetingFixture = []byte("@RSYNCD: 31.0\n")

func runRsync(t *testing.T, serverConn net.Conn, hp *fakeHoneypot) chan error {
	t.Helper()
	prev := rsyncChallenge
	rsyncChallenge = func() (string, error) { return "c2VjcmV0Y2hhbGxlbmdlIQ", nil }
	t.Cleanup(func() { rsyncChallenge = prev })
	done := make(chan error, 1)
	go func() {
		done <- HandleRsync(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return done
}

func requireRsyncEvent(t *testing.T, done chan error, hp *fakeHoneypot) []parsedRsync {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	require.Equal(t, "rsync", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedRsync)
	require.True(t, ok, "decoded should be []parsedRsync")
	return events
}

// rsyncClient reads the greeting and returns helpers to talk to the handler.
func rsyncClient(t *testing.T, client net.Conn) (send func(string), expect func(string)) {
	t.Helper()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(client)
	send = func(line string) {
		t.Helper()
		_, err := client.Write([]byte(line))
		require.NoError(t, err)
	}
	expect = func(want string) {
		t.Helper()
		got := make([]byte, len(want))
		_, err := io.ReadFull(r, got)
		require.NoError(t, err)
		require.Equal(t, want, string(got))
	}
	expect(rsync.Greeting)
	return send, expect
}

func TestHandleRsyncAuthFails(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)

	send, expect := rsyncClient(t, client)
	send("@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n")
	send("backup\n")
	expect("@RSYNCD: AUTHREQD c2VjcmV0Y2hhbGxlbmdlIQ\n")
	send("root fKQLnHeZxhRbHalXnTnOqg\n")
	expect("@ERROR: auth failed on module backup\n")

	require.Equal(t, []parsedRsync{
		{Direction: "write", Status: "greeting", Payload: []byte(rsync.Greeting)},
		{Direction: "read", Command: "version", Version: "31.0", Digests: "sha512 sha256 sha1 md5 md4", Payload: []byte("@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n")},
		{Direction: "read", Command: "module", Path: "backup", Payload: []byte("backup\n")},
		{Direction: "write", Status: "authreqd", Payload: []byte("@RSYNCD: AUTHREQD c2VjcmV0Y2hhbGxlbmdlIQ\n")},
		{Direction: "read", Command: "auth", Path: "backup", Username: "root", Response: "fKQLnHeZxhRbHalXnTnOqg", Payload: []byte("root fKQLnHeZxhRbHalXnTnOqg\n")},
		{Direction: "write", Status: "auth-failed", Payload: []byte("@ERROR: auth failed on module backup\n")},
	}, requireRsyncEvent(t, done, hp))
}

func TestHandleRsyncList(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)

	send, expect := rsyncClient(t, client)
	send(string(rsyncGreetingFixture))
	send("#list\n")
	expect(string(rsync.ModuleList()))

	require.Equal(t, []parsedRsync{
		{Direction: "write", Status: "greeting", Payload: []byte(rsync.Greeting)},
		{Direction: "read", Command: "version", Version: "31.0", Payload: rsyncGreetingFixture},
		{Direction: "read", Command: "list", Payload: []byte("#list\n")},
		{Direction: "write", Status: "list", Payload: rsync.ModuleList()},
	}, requireRsyncEvent(t, done, hp))
}

// TestHandleRsyncRepeatedGreeting replays the captured session: the client
// sends its version line twice, so the second one is taken as a module name,
// as rsyncd does.
func TestHandleRsyncRepeatedGreeting(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)

	send, expect := rsyncClient(t, client)
	send(string(rsyncGreetingFixture))
	send(string(rsyncGreetingFixture))
	expect("@ERROR: Unknown module '@RSYNCD: 31.0'\n")

	require.Equal(t, []parsedRsync{
		{Direction: "write", Status: "greeting", Payload: []byte(rsync.Greeting)},
		{Direction: "read", Command: "version", Version: "31.0", Payload: rsyncGreetingFixture},
		{Direction: "read", Command: "module", Path: "@RSYNCD: 31.0", Payload: rsyncGreetingFixture},
		{Direction: "write", Status: "unknown-module", Payload: []byte("@ERROR: Unknown module '@RSYNCD: 31.0'\n")},
	}, requireRsyncEvent(t, done, hp))
}

func TestHandleRsyncProtocolError(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)

	send, expect := rsyncClient(t, client)
	send("www\n")
	expect(rsync.ProtocolError)

	require.Equal(t, []parsedRsync{
		{Direction: "write", Status: "greeting", Payload: []byte(rsync.Greeting)},
		{Direction: "read", Payload: []byte("www\n")},
		{Direction: "write", Status: "protocol-error", Payload: []byte(rsync.ProtocolError)},
	}, requireRsyncEvent(t, done, hp))
}

func TestHandleRsyncEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)
	_, _ = rsyncClient(t, client)
	require.NoError(t, client.Close())

	require.Equal(t, []parsedRsync{
		{Direction: "write", Status: "greeting", Payload: []byte(rsync.Greeting)},
	}, requireRsyncEvent(t, done, hp))
}

func TestHandleRsyncLongLineTruncated(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)
	_, _ = rsyncClient(t, client)
	// the handler hangs up mid-write, so the write error is expected
	go func() { _, _ = client.Write([]byte(strings.Repeat("A", 2*rsyncMaxLine))) }()

	events := requireRsyncEvent(t, done, hp)
	require.Len(t, events, 2)
	require.True(t, events[1].Truncated)
	require.Len(t, events[1].Payload, rsyncMaxLine)
}

func TestHandleRsyncChallengeError(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runRsync(t, serverConn, hp)
	rsyncChallenge = func() (string, error) { return "", errors.New("no entropy") }

	send, _ := rsyncClient(t, client)
	send(string(rsyncGreetingFixture))
	send("www\n")

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedRsync)
	require.True(t, ok)
	require.Len(t, events, 3)
	require.Equal(t, "www", events[2].Path)
}
