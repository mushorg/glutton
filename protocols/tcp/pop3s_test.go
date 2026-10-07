package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func runPOP3S(t *testing.T, serverConn net.Conn, hp *fakeHoneypot) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- HandlePOP3S(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return done
}

func waitDone(t *testing.T, done chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
}

func requireSingleEvent(t *testing.T, hp *fakeHoneypot) []parsedPOP3 {
	t.Helper()
	produced := waitProduced(t, hp)
	require.Equal(t, "pop3s", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedPOP3)
	require.True(t, ok, "decoded should be []parsedPOP3")
	return events
}

func TestHandlePOP3SSession(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3S(t, serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
	require.NoError(t, tlsClient.Handshake())
	r := bufio.NewReader(tlsClient)
	expect := func(want string) {
		t.Helper()
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want, line)
	}
	send := func(line string) {
		t.Helper()
		_, err := tlsClient.Write([]byte(line))
		require.NoError(t, err)
	}

	expect("+OK Dovecot ready.\r\n")
	send("USER bob\r\n")
	expect("+OK\r\n")
	send("PASS hunter2\r\n")
	expect("-ERR [AUTH] Authentication failed.\r\n")
	send("QUIT\r\n")
	expect("+OK Logging out.\r\n")
	waitDone(t, done)

	events := requireSingleEvent(t, hp)
	require.Len(t, events, 8)
	require.Equal(t, "tls", events[0].Command)
	require.Equal(t, "mail.example.com", events[0].ServerName)
	require.Equal(t, byte(0x16), events[0].Payload[0])
	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte("+OK Dovecot ready.\r\n")},
		{Direction: "read", Command: "USER", Username: "bob", Payload: []byte("USER bob\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK\r\n")},
		{Direction: "read", Command: "PASS", Payload: []byte("PASS hunter2\r\n")},
		{Direction: "write", Status: "-ERR", Payload: []byte("-ERR [AUTH] Authentication failed.\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("QUIT\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK Logging out.\r\n")},
	}, events[1:])
}

func TestHandlePOP3SConnectAndClose(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runPOP3S(t, serverConn, hp)
	require.NoError(t, client.Close())
	waitDone(t, done)
	require.Empty(t, requireSingleEvent(t, hp))
}

func TestHandlePOP3SNonTLSClient(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3S(t, serverConn, hp)

	go func() { _, _ = client.Write([]byte("USER bob\r\nPASS x\r\n")) }()
	waitDone(t, done)

	events := requireSingleEvent(t, hp)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "tls", events[0].Command)
	require.Equal(t, []byte("USER bob\r\nPASS x\r\n"), events[0].Payload)
}
