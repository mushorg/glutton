package tcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
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

	expect("220 mail.localdomain ESMTP ready")
	send("HELO example.com")
	expect("250 mail.localdomain Hello example.com")
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
		{Direction: "write", Status: "220", Payload: []byte("220 mail.localdomain ESMTP ready\r\n")},
		{Direction: "read", Command: "HELO", Payload: []byte("HELO example.com\r\n")},
		{Direction: "write", Status: "250", Payload: []byte("250 mail.localdomain Hello example.com\r\n")},
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
	require.Equal(t, "220 mail.localdomain ESMTP ready\r\n", line)

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

	expect("220 mail.localdomain ESMTP ready")
	send("ehlo scanner")
	expect("250-mail.localdomain Hello scanner")
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

	ehlo := "250-mail.localdomain Hello scanner\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 HELP\r\n"
	want := []parsedSMTP{
		{Direction: "write", Status: "220", Payload: []byte("220 mail.localdomain ESMTP ready\r\n")},
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

// smtpSession drives handleSMTP over net.Pipe and counts calls to sleep.
type smtpSession struct {
	t      *testing.T
	client net.Conn
	reader *bufio.Reader
	hp     *fakeHoneypot
	done   chan error
	sleeps int
}

func startSMTPSession(t *testing.T) *smtpSession {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	s := &smtpSession{t: t, client: client, reader: bufio.NewReader(client), hp: newFakeHoneypot(), done: make(chan error, 1)}
	server := newSMTPServer(serverConn)
	server.sleep = func() error { s.sleeps++; return nil }
	go func() {
		s.done <- handleSMTP(context.Background(), server, connection.Metadata{}, &recordingLogger{}, s.hp)
	}()
	return s
}

func (s *smtpSession) expect(want string) {
	s.t.Helper()
	require.NoError(s.t, s.client.SetReadDeadline(time.Now().Add(2*time.Second)))
	line, err := s.reader.ReadString('\n')
	require.NoError(s.t, err)
	require.Equal(s.t, want+"\r\n", line)
}

func (s *smtpSession) send(line string) {
	s.t.Helper()
	require.NoError(s.t, s.client.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := s.client.Write([]byte(line + "\r\n"))
	require.NoError(s.t, err)
}

// finish waits for the handler and returns the single produced event's frames.
func (s *smtpSession) finish() []parsedSMTP {
	s.t.Helper()
	select {
	case err := <-s.done:
		require.NoError(s.t, err)
	case <-time.After(2 * time.Second):
		s.t.Fatal("handler did not finish")
	}
	produced := waitProduced(s.t, s.hp)
	require.Equal(s.t, "smtp", produced.protocol)
	select {
	case extra := <-s.hp.produced:
		s.t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedSMTP)
	require.True(s.t, ok, "decoded should be []parsedSMTP")
	return events
}

func TestHandleSMTPCommandSequence(t *testing.T) {
	s := startSMTPSession(t)
	s.expect("220 mail.localdomain ESMTP ready")
	s.send("HELO User")
	s.expect("250 mail.localdomain Hello User")
	s.send("RCPT TO:<bob@example.org>")
	s.expect("503 5.5.1 Bad sequence of commands")
	s.send("DATA")
	s.expect("503 5.5.1 Bad sequence of commands")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("503 5.5.1 Error: nested MAIL command")
	s.send("DATA")
	s.expect("503 5.5.1 Bad sequence of commands")
	for i := 0; i < maxRecipients; i++ {
		s.send(fmt.Sprintf("RCPT TO:<rcpt%d@example.org>", i))
		s.expect("250 OK")
	}
	s.send("RCPT TO:<one-too-many@example.org>")
	s.expect("452 4.5.3 Too many recipients")
	s.send("DATA")
	s.expect("354 End data with <CRLF>.<CRLF>")
	s.send("hi")
	s.send(".")
	s.expect("250 OK")
	// a completed DATA ends the transaction
	s.send("RCPT TO:<bob@example.org>")
	s.expect("503 5.5.1 Bad sequence of commands")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("RSET")
	s.expect("250 OK")
	s.send("RCPT TO:<bob@example.org>")
	s.expect("503 5.5.1 Bad sequence of commands")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("EHLO again")
	for _, line := range []string{"250-mail.localdomain Hello again", "250-PIPELINING", "250-SIZE 10240000", "250-AUTH PLAIN LOGIN", "250-8BITMIME", "250 HELP"} {
		s.expect(line)
	}
	s.send("RCPT TO:<bob@example.org>")
	s.expect("503 5.5.1 Bad sequence of commands")
	s.send("QUIT")
	s.expect("221 Bye")

	events := s.finish()
	// sleep only runs before the greeting and after the DATA body
	require.Equal(t, 2, s.sleeps)
	require.Equal(t, "503", events[4].Status)
	require.Equal(t, "DATA", events[5].Command)
	require.Equal(t, "503", events[6].Status)
}

func TestHandleSMTPDataTruncated(t *testing.T) {
	s := startSMTPSession(t)
	s.expect("220 mail.localdomain ESMTP ready")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("RCPT TO:<bob@example.org>")
	s.expect("250 OK")
	s.send("DATA")
	s.expect("354 End data with <CRLF>.<CRLF>")
	for i := 0; i < maxDataRead+100; i++ {
		s.send("NOOP body line")
	}
	s.send(".")
	s.expect("250 OK")
	long := "NOOP " + strings.Repeat("x", 2*maxLineBytes)
	s.send(long)
	s.expect("250 OK")
	s.send("QUIT")
	s.expect("221 Bye")

	events := s.finish()
	require.Len(t, events, 13)
	data := events[7]
	require.Equal(t, "read", data.Direction)
	require.Equal(t, "DATA", data.Command)
	require.True(t, data.Truncated)
	require.Equal(t, strings.Repeat("NOOP body line\r\n", maxDataRead), string(data.Payload))
	require.Equal(t, parsedSMTP{Direction: "write", Status: "250", Payload: []byte("250 OK\r\n")}, events[8])
	require.Equal(t, parsedSMTP{Direction: "read", Command: "NOOP", Payload: []byte(long[:maxLineBytes]), Truncated: true}, events[9])
	require.Equal(t, "250", events[10].Status)
	require.Equal(t, "QUIT", events[11].Command)
}

func TestHandleSMTPDataByteCap(t *testing.T) {
	s := startSMTPSession(t)
	s.expect("220 mail.localdomain ESMTP ready")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("RCPT TO:<bob@example.org>")
	s.expect("250 OK")
	s.send("DATA")
	s.expect("354 End data with <CRLF>.<CRLF>")
	// one overlong body line
	s.send(strings.Repeat("A", maxLineBytes+10))
	s.send(".")
	s.expect("250 OK")
	s.send("QUIT")
	s.expect("221 Bye")

	events := s.finish()
	data := events[7]
	require.Equal(t, "DATA", data.Command)
	require.True(t, data.Truncated)
	require.Equal(t, strings.Repeat("A", maxLineBytes), string(data.Payload))
	require.Equal(t, "250", events[8].Status)
}

func TestHandleSMTPDataAtLineCap(t *testing.T) {
	s := startSMTPSession(t)
	s.expect("220 mail.localdomain ESMTP ready")
	s.send("MAIL FROM:<alice@example.com>")
	s.expect("250 OK")
	s.send("RCPT TO:<bob@example.org>")
	s.expect("250 OK")
	s.send("DATA")
	s.expect("354 End data with <CRLF>.<CRLF>")
	for i := 0; i < maxDataRead; i++ {
		s.send("line")
	}
	s.send(".")
	s.expect("250 OK")
	s.send("QUIT")
	s.expect("221 Bye")

	data := s.finish()[7]
	require.False(t, data.Truncated)
	require.Equal(t, strings.Repeat("line\r\n", maxDataRead)+".\r\n", string(data.Payload))
}
