package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/pop3"
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

	expect(pop3.Greeting)
	send("USER bob\r\n")
	expect("+OK\r\n")
	send("PASS hunter2\r\n")
	expect("-ERR [AUTH] Authentication failed.\r\n")
	send("APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n")
	expect("-ERR [AUTH] Authentication failed.\r\n")
	send("QUIT\r\n")
	expect("+OK Logging out.\r\n")

	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte(pop3.Greeting)},
		{Direction: "read", Command: "USER", Username: "bob", Payload: []byte("USER bob\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK\r\n")},
		{Direction: "read", Command: "PASS", Password: "hunter2", Payload: []byte("PASS hunter2\r\n")},
		{Direction: "write", Status: "-ERR", Payload: []byte("-ERR [AUTH] Authentication failed.\r\n")},
		{Direction: "read", Command: "APOP", Username: "mrose", Digest: "c4c9334bac560ecc979e58001b3e22fb", Payload: []byte("APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n")},
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

// TestHandlePOP3Capa replays the plaintext tcp/110 fingerprint from Ochi event
// fc4e9f1c-6d98-43f2-8cac-6e7fe9f5f064: greeting, CAPA, then the client hangs
// up. The catch-all used to answer CAPA with random bytes.
func TestHandlePOP3Capa(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(client)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "+OK Dovecot (Ubuntu) ready.\r\n", line)
	_, err = client.Write([]byte("CAPA\r\n"))
	require.NoError(t, err)
	capa := pop3.Capabilities(false)
	got := make([]byte, len(capa))
	_, err = io.ReadFull(r, got)
	require.NoError(t, err)
	require.Equal(t, capa, string(got))
	require.NoError(t, client.Close())

	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte("+OK Dovecot (Ubuntu) ready.\r\n")},
		{Direction: "read", Command: "CAPA", Payload: []byte("CAPA\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte(capa)},
	}, requirePOP3Event(t, done, hp))
}

// pop3TLSHelloPrefix is the part of a Go crypto/tls ClientHello that reached
// the plaintext handler in Ochi event 6689b801-1feb-4207-8193-86a7940ae06b
// (scan.visionheight.com on tcp/110), before the client hung up: the record
// announces 243 bytes, 133 arrived as four 0x0a-terminated "lines".
var pop3TLSHelloPrefix = []byte{
	0x16, 0x03, 0x01, 0x00, 0xee, 0x01, 0x00, 0x00, 0xea, 0x03, 0x03, 0x8a, 0x7a, 0xf6, 0xcc, 0x3a,
	0xd2, 0xa7, 0xff, 0x13, 0x02, 0x1a, 0xe6, 0x2f, 0x42, 0xd3, 0x23, 0x64, 0x7e, 0x7d, 0x32, 0xb0,
	0x13, 0x9f, 0xf6, 0xd8, 0x21, 0x85, 0xa6, 0x76, 0x7a, 0x4b, 0x46, 0x20, 0xea, 0x68, 0x16, 0x2f,
	0xde, 0x61, 0x0d, 0xca, 0x9d, 0xed, 0x28, 0x18, 0x38, 0xb8, 0xbd, 0x48, 0xd6, 0xc8, 0x4a, 0x00,
	0xb3, 0x05, 0x6c, 0x64, 0x9e, 0xcd, 0x8d, 0xcf, 0x1a, 0x1e, 0xac, 0x22, 0x00, 0x26, 0xcc, 0xa8,
	0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14,
	0xc0, 0x0a,
	0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a,
	0x13, 0x03, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0x7b, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0a,
	0x00, 0x0a,
}

func requirePOP3Produced(t *testing.T, done chan error, hp *fakeHoneypot) producedTCP {
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
	return produced
}

// TestHandlePOP3ImplicitTLS covers a client that starts TLS on tcp/110
// instead of sending a command: the handler terminates TLS, greets again
// over TLS and keeps serving POP3.
func TestHandlePOP3ImplicitTLS(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, pop3.Greeting, line)

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
	require.NoError(t, tc.Handshake())
	r := bufio.NewReader(tc)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, pop3.Greeting, line)
	_, err = io.WriteString(tc, "USER bob\r\nPASS hunter2\r\n")
	require.NoError(t, err)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "+OK\r\n", line)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "-ERR [AUTH] Authentication failed.\r\n", line)
	require.NoError(t, tc.Close())

	produced := requirePOP3Produced(t, done, hp)
	require.NotNil(t, produced.tls)
	require.Equal(t, "mail.example.com", produced.tls.ServerName)
	require.NotEmpty(t, produced.tls.JA4)
	require.Contains(t, produced.stack, "tls")
	events := produced.decoded.([]parsedPOP3)
	require.Len(t, events, 7)
	require.Equal(t, parsedPOP3{Direction: "write", Status: "+OK", Payload: []byte(pop3.Greeting)}, events[0])
	require.Equal(t, "read", events[1].Direction)
	require.Equal(t, "tls", events[1].Command)
	require.Equal(t, "mail.example.com", events[1].ServerName)
	require.Equal(t, byte(0x16), events[1].Payload[0])
	require.Equal(t, produced.tls.Hello, events[1].Payload)
	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte(pop3.Greeting)},
		{Direction: "read", Command: "USER", Username: "bob", Payload: []byte("USER bob\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte("+OK\r\n")},
		{Direction: "read", Command: "PASS", Password: "hunter2", Payload: []byte("PASS hunter2\r\n")},
		{Direction: "write", Status: "-ERR", Payload: []byte("-ERR [AUTH] Authentication failed.\r\n")},
	}, events[2:])
}

// TestHandlePOP3TruncatedClientHello replays the captured hello prefix and
// hangs up: one tls frame with the bytes, no -ERR replies, and the event is
// still produced.
func TestHandlePOP3TruncatedClientHello(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	_, err = client.Write(pop3TLSHelloPrefix)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced := requirePOP3Produced(t, done, hp)
	require.NotNil(t, produced.tls)
	require.Contains(t, produced.stack, "tls")
	require.Equal(t, []parsedPOP3{
		{Direction: "write", Status: "+OK", Payload: []byte(pop3.Greeting)},
		{Direction: "read", Command: "tls", Payload: pop3TLSHelloPrefix},
	}, produced.decoded.([]parsedPOP3))
}

func TestHandlePOP3STLS(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	pr := bufio.NewReader(client)
	line, err := pr.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, pop3.Greeting, line)
	_, err = client.Write([]byte("STLS\r\n"))
	require.NoError(t, err)
	line, err = pr.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "+OK Begin TLS negotiation now.\r\n", line)

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "pop.example.com"})
	require.NoError(t, tc.Handshake())
	_, err = io.WriteString(tc, "CAPA\r\nSTLS\r\n")
	require.NoError(t, err)
	r := bufio.NewReader(tc)
	capa := pop3.Capabilities(true)
	got := make([]byte, len(capa))
	_, err = io.ReadFull(r, got)
	require.NoError(t, err)
	require.Equal(t, capa, string(got))
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "-ERR TLS is already active.\r\n", line)
	require.NoError(t, tc.Close())

	produced := requirePOP3Produced(t, done, hp)
	require.NotNil(t, produced.tls)
	require.Equal(t, "pop.example.com", produced.tls.ServerName)
	events := produced.decoded.([]parsedPOP3)
	require.Len(t, events, 8)
	require.Equal(t, parsedPOP3{Direction: "read", Command: "STLS", Payload: []byte("STLS\r\n")}, events[1])
	require.Equal(t, parsedPOP3{Direction: "write", Status: "+OK", Payload: []byte("+OK Begin TLS negotiation now.\r\n")}, events[2])
	require.Equal(t, "tls", events[3].Command)
	require.Equal(t, "pop.example.com", events[3].ServerName)
	require.Equal(t, []parsedPOP3{
		{Direction: "read", Command: "CAPA", Payload: []byte("CAPA\r\n")},
		{Direction: "write", Status: "+OK", Payload: []byte(capa)},
		{Direction: "read", Command: "STLS", Payload: []byte("STLS\r\n")},
		{Direction: "write", Status: "-ERR", Payload: []byte("-ERR TLS is already active.\r\n")},
	}, events[4:])
}

// TestHandlePOP3STLSNotTLS covers a client that asks for STLS and then keeps
// talking plaintext: the handshake fails and the event is still produced.
func TestHandlePOP3STLSNotTLS(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := runPOP3(serverConn, hp)

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	go func() {
		pr := bufio.NewReader(client)
		_, _ = pr.ReadString('\n')
		_, _ = client.Write([]byte("STLS\r\n"))
		_, _ = pr.ReadString('\n')
		_, _ = client.Write([]byte("QUIT\r\n"))
		_, _ = io.Copy(io.Discard, pr)
	}()

	produced := requirePOP3Produced(t, done, hp)
	events := produced.decoded.([]parsedPOP3)
	require.Len(t, events, 4)
	require.Equal(t, "tls", events[3].Command)
	require.Equal(t, []byte("QUIT\r\n"), events[3].Payload)
	require.NoError(t, client.Close())
}
