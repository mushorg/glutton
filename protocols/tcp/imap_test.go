package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/imap"
	"github.com/stretchr/testify/require"
)

type imapTest struct {
	t      *testing.T
	client net.Conn
	r      *bufio.Reader
	hp     *fakeHoneypot
	done   chan error
}

func startIMAP(t *testing.T, md connection.Metadata) *imapTest {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleIMAP(context.Background(), serverConn, md, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return &imapTest{t: t, client: client, r: bufio.NewReader(client), hp: hp, done: done}
}

func (m *imapTest) expect(lines ...string) {
	m.t.Helper()
	for _, want := range lines {
		line, err := m.r.ReadString('\n')
		require.NoError(m.t, err)
		require.Equal(m.t, want, line)
	}
}

func (m *imapTest) send(data string) {
	m.t.Helper()
	_, err := io.WriteString(m.client, data)
	require.NoError(m.t, err)
}

func (m *imapTest) event() producedTCP {
	m.t.Helper()
	select {
	case err := <-m.done:
		require.NoError(m.t, err)
	case <-time.After(5 * time.Second):
		m.t.Fatal("handler did not finish")
	}
	produced := waitProduced(m.t, m.hp)
	require.Equal(m.t, "imap", produced.protocol)
	select {
	case extra := <-m.hp.produced:
		m.t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	return produced
}

func imapWrite(status, data string) parsedIMAP {
	return parsedIMAP{Direction: "write", Status: status, Payload: []byte(data)}
}

// Seen on tcp/993 (Ochi live stream 2026-10-22 22:01 UTC,
// eggs.scanf.shodan.io): after the TLS handshake the client waits for the
// server-first greeting, then hangs up.
func TestHandleIMAPSGreetingThenDisconnect(t *testing.T) {
	m := startIMAP(t, connection.Metadata{TLS: &connection.TLSInfo{Version: "TLS 1.2"}})
	m.expect(imap.Greeting(true))
	require.NoError(t, m.client.Close())
	produced := m.event()
	require.Equal(t, []byte(imap.Greeting(true)), produced.payload)
	require.Equal(t, []parsedIMAP{imapWrite("OK", imap.Greeting(true))}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleIMAPLoginGuesses(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	m.send("a001 CAPABILITY\r\n")
	m.expect("* CAPABILITY "+imap.Capabilities(false)+"\r\n",
		"a001 OK Pre-login capabilities listed, post-login capabilities have more.\r\n")
	m.send("a002 LOGIN admin \"pa ss\"\r\n")
	m.expect("a002 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
	m.send("a003 LOGIN {4}\r\n")
	m.expect(imap.LiteralContinue)
	m.send("root {6+}\r\ntoor12\r\n")
	m.expect("a003 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
	m.send("a004 LOGOUT\r\n")
	m.expect("* BYE Logging out\r\n", "a004 OK Logout completed.\r\n")

	produced := m.event()
	require.Equal(t, []parsedIMAP{
		imapWrite("OK", imap.Greeting(false)),
		{Direction: "read", Tag: "a001", Command: "CAPABILITY", Payload: []byte("a001 CAPABILITY\r\n")},
		imapWrite("OK", "* CAPABILITY "+imap.Capabilities(false)+"\r\na001 OK Pre-login capabilities listed, post-login capabilities have more.\r\n"),
		{Direction: "read", Tag: "a002", Command: "LOGIN", Username: "admin", Password: "pa ss", Payload: []byte("a002 LOGIN admin \"pa ss\"\r\n")},
		imapWrite("NO", "a002 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"),
		{Direction: "read", Tag: "a003", Command: "LOGIN", Username: "root", Password: "toor12", Payload: []byte("a003 LOGIN {4}\r\nroot {6+}\r\ntoor12\r\n")},
		imapWrite("+", imap.LiteralContinue),
		imapWrite("NO", "a003 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"),
		{Direction: "read", Tag: "a004", Command: "LOGOUT", Payload: []byte("a004 LOGOUT\r\n")},
		imapWrite("OK", "* BYE Logging out\r\na004 OK Logout completed.\r\n"),
	}, produced.decoded)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleIMAPAuthenticate(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	// SASL-IR: \0admin\0secret
	m.send("1 AUTHENTICATE PLAIN AGFkbWluAHNlY3JldA==\r\n")
	m.expect("1 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
	m.send("2 AUTHENTICATE PLAIN\r\n")
	m.expect(imap.SASLContinue)
	m.send("AHRlc3QAMTIzNDU2\r\n") // \0test\0123456
	m.expect("2 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
	m.send("3 AUTHENTICATE LOGIN\r\n")
	m.expect(imap.LoginUserPrompt)
	m.send("dXNlcg==\r\n") // user
	m.expect(imap.LoginPassPrompt)
	m.send("cGFzc3dvcmQ=\r\n") // password
	m.expect("3 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
	m.send("4 AUTHENTICATE PLAIN\r\n")
	m.expect(imap.SASLContinue)
	m.send("*\r\n")
	m.expect("4 BAD Authentication aborted by client.\r\n")
	m.send("5 AUTHENTICATE CRAM-MD5\r\n")
	m.expect("5 NO Unsupported authentication mechanism.\r\n")
	require.NoError(t, m.client.Close())

	events := m.event().decoded.([]parsedIMAP)
	require.Equal(t, parsedIMAP{Direction: "read", Tag: "1", Command: "AUTHENTICATE", Mechanism: "PLAIN", Username: "admin", Password: "secret",
		Payload: []byte("1 AUTHENTICATE PLAIN AGFkbWluAHNlY3JldA==\r\n")}, events[1])
	require.Equal(t, parsedIMAP{Direction: "read", Command: "sasl-response", Username: "test", Password: "123456",
		Payload: []byte("AHRlc3QAMTIzNDU2\r\n")}, events[5])
	require.Equal(t, "user", events[9].Username)
	require.Equal(t, "password", events[11].Password)
	require.Equal(t, "LOGIN", events[7].Mechanism)
	require.Equal(t, "BAD", events[len(events)-3].Status)
	require.Equal(t, "CRAM-MD5", events[len(events)-2].Mechanism)
	require.Equal(t, "NO", events[len(events)-1].Status)
}

func TestHandleIMAPStartTLS(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	m.send("s1 STARTTLS\r\n")
	m.expect("s1 OK Begin TLS negotiation now.\r\n")
	tc := tls.Client(m.client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
	require.NoError(t, tc.Handshake())
	_, err := io.WriteString(tc, "s2 CAPABILITY\r\n")
	require.NoError(t, err)
	r := bufio.NewReader(tc)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "* CAPABILITY "+imap.Capabilities(true)+"\r\n", line)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	_, err = io.WriteString(tc, "s3 STARTTLS\r\n")
	require.NoError(t, err)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "s3 BAD TLS is already active.\r\n", line)
	require.NoError(t, tc.Close())

	events := m.event().decoded.([]parsedIMAP)
	require.Equal(t, "tls", events[3].Command)
	require.Equal(t, "mail.example.com", events[3].ServerName)
	require.NotEmpty(t, events[3].Payload)
	require.Equal(t, "CAPABILITY", events[4].Command)
	require.NotContains(t, string(events[5].Payload), "STARTTLS")
}

func TestHandleIMAPUntaggedAndUnknown(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	m.send("\r\n")
	m.expect("* BAD Error in IMAP command received by server.\r\n")
	m.send("x SELECT INBOX\r\n")
	m.expect("x BAD Error in IMAP command SELECT: Command not permitted in this state.\r\n")
	m.send("GET / HTTP/1.1\r\n")
	m.expect("GET BAD Error in IMAP command received by server.\r\n")
	require.NoError(t, m.client.Close())

	events := m.event().decoded.([]parsedIMAP)
	require.Equal(t, parsedIMAP{Direction: "read", Payload: []byte("\r\n")}, events[1])
	require.Equal(t, parsedIMAP{Direction: "read", Tag: "x", Command: "SELECT", Payload: []byte("x SELECT INBOX\r\n")}, events[3])
	require.Equal(t, "/", events[5].Command)
}

func TestHandleIMAPMaxCommands(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	for range imapMaxCommands {
		m.send("n NOOP\r\n")
		m.expect("n OK NOOP completed.\r\n")
	}
	produced := m.event()
	require.Len(t, produced.decoded.([]parsedIMAP), 1+2*imapMaxCommands)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}

func TestHandleIMAPOversizeLine(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	go func() { _, _ = io.WriteString(m.client, "a LOGIN "+strings.Repeat("A", imapMaxLine)+"\r\n") }()
	produced := m.event()
	events := produced.decoded.([]parsedIMAP)
	require.Len(t, events, 2)
	require.True(t, events[1].Truncated)
	require.Len(t, events[1].Payload, imapMaxLine)
	require.Equal(t, connection.EndReadError, produced.endReason)
}

func TestHandleIMAPOversizeLiteral(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	m.send("a LOGIN {99999}\r\n")
	produced := m.event()
	events := produced.decoded.([]parsedIMAP)
	require.Equal(t, []parsedIMAP{
		imapWrite("OK", imap.Greeting(false)),
		{Direction: "read", Payload: []byte("a LOGIN {99999}\r\n"), Truncated: true},
	}, events)
}

func TestHandleIMAPPartialLine(t *testing.T) {
	m := startIMAP(t, connection.Metadata{})
	m.expect(imap.Greeting(false))
	m.send("a LOG")
	require.NoError(t, m.client.Close())
	produced := m.event()
	require.Equal(t, []parsedIMAP{
		imapWrite("OK", imap.Greeting(false)),
		{Direction: "read", Payload: []byte("a LOG")},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}
