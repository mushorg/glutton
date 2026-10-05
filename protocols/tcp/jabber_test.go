package tcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/jabber"
	"github.com/stretchr/testify/require"
)

const jabberClientStream = "<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

type jabberHarness struct {
	t      *testing.T
	client net.Conn
	hp     *fakeHoneypot
	logger *recordingLogger
	done   chan error
}

func startJabber(t *testing.T) *jabberHarness {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	j := &jabberHarness{t: t, client: client, hp: newFakeHoneypot(), logger: &recordingLogger{}, done: make(chan error, 1)}
	server := newJabberServer(serverConn)
	server.newStreamID = func() string { return "s1" }
	go func() {
		j.done <- handleJabber(context.Background(), server, connection.Metadata{}, j.logger, j.hp)
	}()
	return j
}

func (j *jabberHarness) send(w io.Writer, s string) {
	j.t.Helper()
	_, err := w.Write([]byte(s))
	require.NoError(j.t, err)
}

func (j *jabberHarness) expect(r io.Reader, want ...[]byte) {
	j.t.Helper()
	all := bytes.Join(want, nil)
	got := make([]byte, len(all))
	_, err := io.ReadFull(r, got)
	require.NoError(j.t, err)
	require.Equal(j.t, string(all), string(got))
}

// finish waits for the single produced event and checks no second one follows.
func (j *jabberHarness) finish() (producedTCP, []parsedJabber) {
	j.t.Helper()
	select {
	case err := <-j.done:
		require.NoError(j.t, err)
	case <-time.After(5 * time.Second):
		j.t.Fatal("handler did not return")
	}
	ev := waitProduced(j.t, j.hp)
	require.Equal(j.t, "jabber", ev.protocol)
	require.Empty(j.t, j.hp.produced, "expected exactly one produced event")
	require.Empty(j.t, j.logger.errs)
	frames, ok := ev.decoded.([]parsedJabber)
	require.True(j.t, ok)
	return ev, frames
}

func TestHandleJabberSilentClient(t *testing.T) {
	j := startJabber(t)
	require.NoError(t, j.client.Close())

	ev, frames := j.finish()
	require.Empty(t, frames, "no banner must be sent before the client speaks")
	require.Equal(t, connection.EndClientClose, ev.endReason)
}

func TestHandleJabberStreamHeader(t *testing.T) {
	j := startJabber(t)
	header := jabber.StreamHeader("s1", "example.com")
	features := jabber.Features(true)

	// No trailing newline: the header must be answered without one.
	j.send(j.client, jabberClientStream)
	j.expect(j.client, header, features)
	require.NoError(t, j.client.Close())

	ev, frames := j.finish()
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedJabber{
		{Direction: "read", Command: "stream", Path: "example.com", Payload: []byte(jabberClientStream)},
		{Direction: "write", Command: "stream", Path: "example.com", Payload: header},
		{Direction: "write", Command: "features", Payload: features},
	}, frames)
}

func TestHandleJabberPlainAuth(t *testing.T) {
	j := startJabber(t)
	auth := "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>" +
		base64.StdEncoding.EncodeToString([]byte("\x00admin\x00hunter2")) + "</auth>"

	j.send(j.client, jabberClientStream)
	j.expect(j.client, jabber.StreamHeader("s1", "example.com"), jabber.Features(true))
	j.send(j.client, auth)
	j.expect(j.client, jabber.SASLFailure("not-authorized"), jabber.StreamEnd())
	_, err := j.client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	ev, frames := j.finish()
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Len(t, frames, 6)
	require.Equal(t, parsedJabber{
		Direction: "read", Command: "auth", Mechanism: "PLAIN",
		Username: "admin", Password: "hunter2", Payload: []byte(auth),
	}, frames[3])
	require.Equal(t, parsedJabber{
		Direction: "write", Command: "failure", Status: "not-authorized",
		Payload: jabber.SASLFailure("not-authorized"),
	}, frames[4])
	require.Equal(t, jabber.CmdStreamEnd, frames[5].Command)
}

func TestHandleJabberLegacyIQAuth(t *testing.T) {
	j := startJabber(t)
	get := "<iq type='get' id='a1'><query xmlns='jabber:iq:auth'><username>bill</username></query></iq>"
	set := "<iq type='set' id='a2'><query xmlns='jabber:iq:auth'><username>bill</username><password>Calli0pe</password><resource>r</resource></query></iq>"

	j.send(j.client, jabberClientStream)
	j.expect(j.client, jabber.StreamHeader("s1", "example.com"), jabber.Features(true))
	j.send(j.client, get)
	j.expect(j.client, jabber.IQAuthFields("a1"))
	j.send(j.client, set)
	j.expect(j.client, jabber.IQError("a2", "auth", "not-authorized"), jabber.StreamEnd())

	_, frames := j.finish()
	require.Len(t, frames, 8)
	require.Equal(t, "bill", frames[5].Username)
	require.Equal(t, "Calli0pe", frames[5].Password)
	require.Equal(t, "not-authorized", frames[6].Status)
}

func TestHandleJabberMalformed(t *testing.T) {
	j := startJabber(t)
	probe := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	j.send(j.client, probe)
	_, err := io.ReadAll(j.client)
	require.NoError(t, err)

	ev, frames := j.finish()
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedJabber{{Direction: "read", Payload: []byte(probe)}}, frames)
}

func TestHandleJabberOversize(t *testing.T) {
	j := startJabber(t)
	out := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(j.client)
		out <- b
	}()
	j.send(j.client, jabberClientStream)
	// Writes past the cap fail once the handler closes the pipe.
	_, _ = j.client.Write([]byte("<message><body>" + string(bytes.Repeat([]byte("A"), 2*jabberMaxFrameSize))))

	ev, frames := j.finish()
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Len(t, frames, 5)
	last := frames[3]
	require.Equal(t, "read", last.Direction)
	require.True(t, last.Truncated)
	require.Len(t, last.Payload, jabberMaxFrameSize)
	require.Equal(t, parsedJabber{Direction: "write", Command: "stream-error", Status: "policy-violation", Payload: jabber.StreamError("policy-violation")}, frames[4])
	require.True(t, bytes.HasSuffix(<-out, jabber.StreamError("policy-violation")))
}

func TestHandleJabberMaxFrames(t *testing.T) {
	j := startJabber(t)
	go func() { _, _ = io.Copy(io.Discard, j.client) }()
	j.send(j.client, jabberClientStream)
	for range jabberMaxFrames {
		if _, err := j.client.Write([]byte("<iq type='get' id='x'><ping xmlns='urn:xmpp:ping'/></iq>")); err != nil {
			break
		}
	}

	ev, frames := j.finish()
	require.Equal(t, connection.EndMaxFrames, ev.endReason)
	reads := 0
	for _, f := range frames {
		if f.Direction == "read" {
			reads++
		}
	}
	require.Equal(t, jabberMaxFrames, reads)
}

func TestHandleJabberDirectTLS(t *testing.T) {
	j := startJabber(t)
	tc := tls.Client(j.client, &tls.Config{InsecureSkipVerify: true, ServerName: "chat.example.org"})
	require.NoError(t, tc.Handshake())

	j.send(tc, jabberClientStream)
	j.expect(tc, jabber.StreamHeader("s1", "example.com"), jabber.Features(false))
	require.NoError(t, j.client.Close())

	_, frames := j.finish()
	require.Len(t, frames, 4)
	require.Equal(t, "tls", frames[0].Command)
	require.True(t, frames[0].TLS)
	require.Equal(t, "chat.example.org", frames[0].ServerName)
	require.Equal(t, byte(0x16), frames[0].Payload[0])
	require.Equal(t, parsedJabber{Direction: "read", Command: "stream", Path: "example.com", TLS: true, Payload: []byte(jabberClientStream)}, frames[1])
	require.True(t, frames[3].TLS)
}

func TestHandleJabberStartTLS(t *testing.T) {
	j := startJabber(t)
	j.send(j.client, jabberClientStream)
	j.expect(j.client, jabber.StreamHeader("s1", "example.com"), jabber.Features(true))
	j.send(j.client, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	j.expect(j.client, jabber.Proceed())

	tc := tls.Client(j.client, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"})
	require.NoError(t, tc.Handshake())
	j.send(tc, jabberClientStream)
	j.expect(tc, jabber.StreamHeader("s1", "example.com"), jabber.Features(false))
	require.NoError(t, j.client.Close())

	_, frames := j.finish()
	commands := make([]string, 0, len(frames))
	for _, f := range frames {
		commands = append(commands, f.Direction+":"+f.Command)
	}
	require.Equal(t, []string{
		"read:stream", "write:stream", "write:features",
		"read:starttls", "write:proceed",
		"read:tls", "read:stream", "write:stream", "write:features",
	}, commands)
	require.False(t, frames[4].TLS)
	require.True(t, frames[6].TLS)
}
