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

func TestHandleSMTP(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	server := newSMTPServer(serverConn)
	server.sleep = func() error { return nil }

	done := make(chan error, 1)
	go func() {
		done <- handleSMTP(context.Background(), server, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	expect := func(want string) {
		t.Helper()
		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want+"\r\n", line)
	}
	send := func(line string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err := client.Write([]byte(line + "\r\n"))
		require.NoError(t, err)
	}

	expect("220 Welcome!")
	send("HELO example.com")
	expect("250 Hello! Pleased to meet you.")
	send("MAIL FROM:<alice@example.com>")
	expect("250 OK")
	send("RCPT TO:<bob@example.org>")
	expect("250 OK")
	send("DATA")
	expect("354 End data with <CRLF>.<CRLF>")
	send("Subject: hi")
	send("")
	send("hello bob")
	send(".")
	expect("250 OK")
	send("QUIT")
	expect("221 Bye")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "smtp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedSMTP)
	require.True(t, ok, "decoded should be []parsedSMTP")

	want := []parsedSMTP{
		{Direction: "write", Status: "220", Payload: []byte("220 Welcome!\r\n")},
		{Direction: "read", Command: "HELO", Payload: []byte("HELO example.com\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 Hello! Pleased to meet you.\r\n")},
		{Direction: "read", Command: "MAIL", Mailbox: "alice@example.com", Payload: []byte("MAIL FROM:<alice@example.com>\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "RCPT", Mailbox: "bob@example.org", Payload: []byte("RCPT TO:<bob@example.org>\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "DATA", Payload: []byte("DATA\r\n")},
		{Direction: "write", Status: "354", Payload: []byte("354 End data with <CRLF>.<CRLF>\r\n")},
		{Direction: "read", Command: "DATA", Payload: []byte("Subject: hi\r\n\r\nhello bob\r\n.\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("QUIT\r\n")},
		{Direction: "write", Status: "221", Payload: []byte("221 Bye\r\n")},
	}
	require.Equal(t, want, events)
	require.Equal(t, want[0].Payload, server.events[0].Payload)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleSMTPClientDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	server := newSMTPServer(serverConn)
	server.sleep = func() error { return nil }

	done := make(chan error, 1)
	go func() {
		done <- handleSMTP(context.Background(), server, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "220 Welcome!\r\n", line)

	_, err = client.Write([]byte("XYZZY scanner\r\n"))
	require.NoError(t, err)
	line, err = reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "500 Recheck the command you entered.\r\n", line)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "smtp", produced.protocol)
	events, ok := produced.decoded.([]parsedSMTP)
	require.True(t, ok)
	require.Len(t, events, 3)
	require.Equal(t, "XYZZY", events[1].Command)
	require.Equal(t, "500", events[2].Status)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleSMTPExtendedSession(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	server := newSMTPServer(serverConn)
	server.sleep = func() error { return nil }

	done := make(chan error, 1)
	go func() {
		done <- handleSMTP(context.Background(), server, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	expect := func(want string) {
		t.Helper()
		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want+"\r\n", line)
	}
	send := func(line string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err := client.Write([]byte(line + "\r\n"))
		require.NoError(t, err)
	}

	expect("220 Welcome!")
	send("ehlo scanner")
	expect("250-Hello! Pleased to meet you.")
	expect("250-PIPELINING")
	expect("250-SIZE 10240000")
	expect("250-AUTH PLAIN LOGIN")
	expect("250-8BITMIME")
	expect("250 HELP")
	send("STARTTLS")
	expect("454 4.7.0 TLS not available due to temporary reason")
	send("AUTH LOGIN")
	expect("334 VXNlcm5hbWU6")
	send("YWRtaW4=") // admin
	expect("334 UGFzc3dvcmQ6")
	send("aHVudGVyMg==") // hunter2
	expect("535 5.7.8 Authentication credentials invalid")
	send("AUTH PLAIN AHJvb3QAdG9vcg==") // \x00root\x00toor
	expect("535 5.7.8 Authentication credentials invalid")
	send("AUTH PLAIN")
	expect("334 ")
	send("*")
	expect("501 5.7.0 Authentication cancelled")
	send("AUTH CRAM-MD5")
	expect("504 5.5.4 Unrecognized authentication type")
	send("mail from:<spam@example.com> SIZE=100")
	expect("250 OK")
	send("RCPT TO:<nobody>")
	expect("501 Syntax error in parameters or arguments")
	send("rset")
	expect("250 OK")
	send("NOOP")
	expect("250 OK")
	send("quit")
	expect("221 Bye")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "smtp", produced.protocol)
	events, ok := produced.decoded.([]parsedSMTP)
	require.True(t, ok)

	ehlo := "250-Hello! Pleased to meet you.\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 HELP\r\n"
	want := []parsedSMTP{
		{Direction: "write", Status: "220", Payload: []byte("220 Welcome!\r\n")},
		{Direction: "read", Command: "EHLO", Payload: []byte("ehlo scanner\r\n")},
		{Direction: "write", Status: "250", Payload: []byte(ehlo)},
		{Direction: "read", Command: "STARTTLS", Payload: []byte("STARTTLS\r\n")},
		{Direction: "write", Status: "454", Payload: []byte("454 4.7.0 TLS not available due to temporary reason\r\n")},
		{Direction: "read", Command: "AUTH", Payload: []byte("AUTH LOGIN\r\n")},
		{Direction: "write", Status: "334", Payload: []byte("334 VXNlcm5hbWU6\r\n")},
		{Direction: "read", Command: "AUTH", Username: "admin", Payload: []byte("YWRtaW4=\r\n")},
		{Direction: "write", Status: "334", Payload: []byte("334 UGFzc3dvcmQ6\r\n")},
		{Direction: "read", Command: "AUTH", Payload: []byte("aHVudGVyMg==\r\n")},
		{Direction: "write", Status: "535", Payload: []byte("535 5.7.8 Authentication credentials invalid\r\n")},
		{Direction: "read", Command: "AUTH", Username: "root", Payload: []byte("AUTH PLAIN AHJvb3QAdG9vcg==\r\n")},
		{Direction: "write", Status: "535", Payload: []byte("535 5.7.8 Authentication credentials invalid\r\n")},
		{Direction: "read", Command: "AUTH", Payload: []byte("AUTH PLAIN\r\n")},
		{Direction: "write", Status: "334", Payload: []byte("334 \r\n")},
		{Direction: "read", Command: "AUTH", Payload: []byte("*\r\n")},
		{Direction: "write", Status: "501", Payload: []byte("501 5.7.0 Authentication cancelled\r\n")},
		{Direction: "read", Command: "AUTH", Payload: []byte("AUTH CRAM-MD5\r\n")},
		{Direction: "write", Status: "504", Payload: []byte("504 5.5.4 Unrecognized authentication type\r\n")},
		{Direction: "read", Command: "MAIL", Mailbox: "spam@example.com", Params: "SIZE=100", Payload: []byte("mail from:<spam@example.com> SIZE=100\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "RCPT", Mailbox: "nobody", Payload: []byte("RCPT TO:<nobody>\r\n")},
		{Direction: "write", Status: "501", Payload: []byte("501 Syntax error in parameters or arguments\r\n")},
		{Direction: "read", Command: "RSET", Payload: []byte("rset\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "NOOP", Payload: []byte("NOOP\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("quit\r\n")},
		{Direction: "write", Status: "221", Payload: []byte("221 Bye\r\n")},
	}
	require.Equal(t, want, events)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleSMTPDisconnectDuringAuth(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	server := newSMTPServer(serverConn)
	server.sleep = func() error { return nil }

	done := make(chan error, 1)
	go func() {
		done <- handleSMTP(context.Background(), server, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := reader.ReadString('\n')
	require.NoError(t, err)
	_, err = client.Write([]byte("AUTH LOGIN\r\n"))
	require.NoError(t, err)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "334 VXNlcm5hbWU6\r\n", line)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedSMTP)
	require.True(t, ok)
	require.Len(t, events, 3)
	require.Equal(t, "AUTH", events[1].Command)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}
