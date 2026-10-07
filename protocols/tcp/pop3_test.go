package tcp

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func runPOP3(serverConn net.Conn, hp *fakeHoneypot) chan error {
	done := make(chan error, 1)
	go func() {
		done <- HandlePOP3(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return done
}

func requirePOP3Event(t *testing.T, done chan error, hp *fakeHoneypot) []parsedPOP3 {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	require.Equal(t, "pop3", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedPOP3)
	require.True(t, ok, "decoded should be []parsedPOP3")
	return events
}

func TestHandlePOP3Session(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(client)
	expect := func(want string) {
		t.Helper()
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want, line)
	}
	send := func(line string) {
		t.Helper()
		_, err := client.Write([]byte(line))
		require.NoError(t, err)
	}

	expect("+OK Dovecot ready.\r\n")
	send("USER bob\r\n")
	expect("+OK\r\n")
	send("PASS hunter2\r\n")
	expect("-ERR [AUTH] Authentication failed.\r\n")
	send("QUIT\r\n")
	expect("+OK Logging out.\r\n")

	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte("+OK Dovecot ready.\r\n")},
		{Direction: "read", Command: "USER", Username: "bob", Payload: []byte("USER bob\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK\r\n")},
		{Direction: "read", Command: "PASS", Payload: []byte("PASS hunter2\r\n")},
		{Direction: "write", Status: "-ERR", Payload: []byte("-ERR [AUTH] Authentication failed.\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("QUIT\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK Logging out.\r\n")},
	}, requirePOP3Event(t, done, hp))
}

func TestHandlePOP3EarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)
	_, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.NoError(t, client.Close())

	events := requirePOP3Event(t, done, hp)
	require.Len(t, events, 1)
	require.Equal(t, "write", events[0].Direction)
}

func TestHandlePOP3LongLineTruncated(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)
	go func() {
		_, _ = bufio.NewReader(client).ReadString('\n')
		buf := make([]byte, 2*pop3MaxLine)
		for i := range buf {
			buf[i] = 'A'
		}
		_, _ = client.Write(buf)
	}()

	events := requirePOP3Event(t, done, hp)
	require.Len(t, events, 2)
	require.True(t, events[1].Truncated)
	require.Len(t, events[1].Payload, pop3MaxLine)
}
