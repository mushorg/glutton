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

func TestValidateMail(t *testing.T) {
	require.True(t, validateMail("MAIL FROM:<example@example.com>"), "email regex validation failed")
	require.False(t, validateMail("MAIL FROM:<example.com>"), "email regex validation failed")
}

func TestValidateRCPT(t *testing.T) {
	require.True(t, validateRCPT("RCPT TO:<example@example.com>"), "validate rcpt regex failed")
	require.False(t, validateRCPT("RCPT TO:<example.com>"), "validate rcpt regex failed")
}

func TestSMTPVerb(t *testing.T) {
	require.Equal(t, "HELO", smtpVerb("HELO example.com\r\n"))
	require.Equal(t, "MAIL", smtpVerb("mail from:<a@b.c>\r\n"))
	require.Equal(t, "RCPT", smtpVerb("RCPT TO:<a@b.c>\r\n"))
	require.Equal(t, "DATA", smtpVerb("DATA\r\n"))
	require.Equal(t, "", smtpVerb("\r\n"))
}

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
		{Direction: "write", Payload: []byte("220 Welcome!\r\n")},
		{Direction: "read", Command: "HELO", Payload: []byte("HELO example.com\r\n")},
		{Direction: "write", Payload: []byte("250 Hello! Pleased to meet you.\r\n")},
		{Direction: "read", Command: "MAIL", Payload: []byte("MAIL FROM:<alice@example.com>\r\n")},
		{Direction: "write", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "RCPT", Payload: []byte("RCPT TO:<bob@example.org>\r\n")},
		{Direction: "write", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "DATA", Payload: []byte("DATA\r\n")},
		{Direction: "write", Payload: []byte("354 End data with <CRLF>.<CRLF>\r\n")},
		{Direction: "read", Command: "DATA", Payload: []byte("Subject: hi\r\n\r\nhello bob\r\n.\r\n")},
		{Direction: "write", Payload: []byte("250 OK\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("QUIT\r\n")},
		{Direction: "write", Payload: []byte("221 Bye\r\n")},
	}
	require.Equal(t, want, events)
	require.Equal(t, want[0].Payload, server.events[0].Payload)
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

	_, err = client.Write([]byte("EHLO scanner\r\n"))
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
	require.Equal(t, "EHLO", events[1].Command)
}
