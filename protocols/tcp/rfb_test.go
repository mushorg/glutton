package tcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/rfb"
	"github.com/stretchr/testify/require"
)

var rfbTestChallenge = bytes.Repeat([]byte{0xab}, rfb.ChallengeLen)

type rfbClient struct {
	t    *testing.T
	conn net.Conn
}

func (c rfbClient) expect(want []byte) {
	c.t.Helper()
	require.NoError(c.t, c.conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	got := make([]byte, len(want))
	_, err := io.ReadFull(c.conn, got)
	require.NoError(c.t, err)
	require.Equal(c.t, want, got)
}

func (c rfbClient) send(data []byte) {
	c.t.Helper()
	require.NoError(c.t, c.conn.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := c.conn.Write(data)
	require.NoError(c.t, err)
}

// startRFB runs the handler on one end of a pipe and returns the other end.
func startRFB(t *testing.T) (rfbClient, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })

	hp := newFakeHoneypot()
	server := newRFBServer(serverConn)
	server.rand = bytes.NewReader(rfbTestChallenge)

	done := make(chan error, 1)
	go func() {
		done <- handleRFB(context.Background(), server, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return rfbClient{t: t, conn: client}, hp, done
}

// finishRFB waits for the handler and returns its single produced event.
func finishRFB(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	require.Equal(t, "rfb", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	return produced
}

func TestHandleRFBVNCAuth38(t *testing.T) {
	c, hp, done := startRFB(t)
	response := bytes.Repeat([]byte{0x01}, rfb.ChallengeLen)
	serverInit := rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.008\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{2})
	c.expect(rfbTestChallenge)
	c.send(response)
	c.expect([]byte{0, 0, 0, 0}) // auth accepted
	c.send([]byte{1})            // ClientInit
	c.expect(serverInit)
	require.NoError(t, c.conn.Close())

	produced := finishRFB(t, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRFB{
		{Direction: "write", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "read", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "write", Command: "Security", SecurityType: "VNCAuthentication,None", Payload: []byte{2, 2, 1}},
		{Direction: "read", Command: "SecurityType", SecurityType: "VNCAuthentication", Payload: []byte{2}},
		{Direction: "write", Command: "VNCAuthChallenge", Challenge: strings.Repeat("ab", 16), Payload: rfbTestChallenge},
		{Direction: "read", Command: "VNCAuthResponse", Response: strings.Repeat("01", 16), Payload: response},
		{Direction: "write", Command: "SecurityResult", Status: "OK", Payload: []byte{0, 0, 0, 0}},
		{Direction: "read", Command: "ClientInit", Payload: []byte{1}},
		{Direction: "write", Command: "ServerInit", Payload: serverInit},
	}, produced.decoded)
}

func TestHandleRFBVNCAuth33(t *testing.T) {
	c, hp, done := startRFB(t)
	response := bytes.Repeat([]byte{0x02}, rfb.ChallengeLen)
	serverInit := rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.003\n"))
	c.expect([]byte{0, 0, 0, 2})
	c.expect(rfbTestChallenge)
	c.send(response)
	c.expect([]byte{0, 0, 0, 0}) // auth accepted, no reason string before 3.8
	c.send([]byte{1})            // ClientInit
	c.expect(serverInit)
	require.NoError(t, c.conn.Close())

	produced := finishRFB(t, hp, done)
	events := produced.decoded.([]parsedRFB)
	require.Len(t, events, 8)
	require.Equal(t, "3.3", events[1].Version)
	require.Equal(t, parsedRFB{Direction: "write", Command: "Security", SecurityType: "VNCAuthentication", Payload: []byte{0, 0, 0, 2}}, events[2])
	require.Equal(t, strings.Repeat("02", 16), events[4].Response)
	require.Equal(t, parsedRFB{Direction: "write", Command: "SecurityResult", Status: "OK", Payload: []byte{0, 0, 0, 0}}, events[5])
	require.Equal(t, "ClientInit", events[6].Command)
	require.Equal(t, "ServerInit", events[7].Command)
}

func TestHandleRFBNoneSession(t *testing.T) {
	c, hp, done := startRFB(t)
	setEncodings := []byte{2, 0, 0, 2, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x11}
	keyDown := []byte{4, 1, 0, 0, 0, 0, 0, 0x61}
	keyUp := []byte{4, 0, 0, 0, 0, 0, 0, 0x61}
	cutText := []byte{6, 0, 0, 0, 0, 0, 0, 2, 'h', 'i'}
	serverInit := rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.008\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{1})
	c.expect([]byte{0, 0, 0, 0})
	c.send([]byte{1})
	c.expect(serverInit)
	c.send(setEncodings)
	c.send(keyDown)
	c.send(keyUp)
	c.send(cutText)
	require.NoError(t, c.conn.Close())

	produced := finishRFB(t, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRFB{
		{Direction: "write", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "read", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "write", Command: "Security", SecurityType: "VNCAuthentication,None", Payload: []byte{2, 2, 1}},
		{Direction: "read", Command: "SecurityType", SecurityType: "None", Payload: []byte{1}},
		{Direction: "write", Command: "SecurityResult", Status: "OK", Payload: []byte{0, 0, 0, 0}},
		{Direction: "read", Command: "ClientInit", Payload: []byte{1}},
		{Direction: "write", Command: "ServerInit", Payload: serverInit},
		{Direction: "read", Command: "SetEncodings", Encodings: []int32{0, -239}, Payload: setEncodings},
		{Direction: "read", Command: "KeyEvent", Key: "a", Payload: keyDown},
		{Direction: "read", Command: "KeyEvent", Payload: keyUp},
		{Direction: "read", Command: "ClientCutText", Text: "hi", Payload: cutText},
	}, produced.decoded)
}

func TestHandleRFBNone37SkipsSecurityResult(t *testing.T) {
	c, hp, done := startRFB(t)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.007\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{1})
	c.send([]byte{0}) // ClientInit follows directly
	c.expect(rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName))
	require.NoError(t, c.conn.Close())

	events := finishRFB(t, hp, done).decoded.([]parsedRFB)
	require.Equal(t, []string{"ProtocolVersion", "ProtocolVersion", "Security", "SecurityType", "ClientInit", "ServerInit"}, rfbCommands(events))
}

func TestHandleRFBUnsupportedSecurityType(t *testing.T) {
	c, hp, done := startRFB(t)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.008\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{19})
	c.expect(rfb.SecurityResult(false, rfb.Version38, "Security type not supported"))

	events := finishRFB(t, hp, done).decoded.([]parsedRFB)
	require.Equal(t, "VeNCrypt", events[3].SecurityType)
	require.Equal(t, "Failed", events[4].Status)
}

func TestHandleRFBCutTextTruncated(t *testing.T) {
	c, hp, done := startRFB(t)
	text := bytes.Repeat([]byte{'x'}, rfbMaxPayload+100)
	msg := append([]byte{6, 0, 0, 0, 0, 0, 0x10, 0x64}, text...)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.008\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{1})
	c.expect([]byte{0, 0, 0, 0})
	c.send([]byte{1})
	c.expect(rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName))
	c.send(msg)
	require.NoError(t, c.conn.Close())

	events := finishRFB(t, hp, done).decoded.([]parsedRFB)
	last := events[len(events)-1]
	require.Equal(t, "ClientCutText", last.Command)
	require.True(t, last.Truncated)
	require.Len(t, last.Payload, 8+rfbMaxPayload)
	require.Len(t, last.Text, rfbMaxPayload)
}

func TestHandleRFBMaxFrames(t *testing.T) {
	c, hp, done := startRFB(t)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 003.008\n"))
	c.expect([]byte{2, 2, 1})
	c.send([]byte{1})
	c.expect([]byte{0, 0, 0, 0})
	c.send([]byte{1})
	c.expect(rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName))
	go func() {
		pointer := []byte{5, 0, 0, 1, 0, 2}
		for range rfbMaxFrames {
			if _, err := c.conn.Write(pointer); err != nil {
				return
			}
		}
	}()

	produced := finishRFB(t, hp, done)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	require.Len(t, produced.decoded.([]parsedRFB), rfbMaxFrames)
}

func TestHandleRFBNotRFB(t *testing.T) {
	c, hp, done := startRFB(t)
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")

	c.expect([]byte("RFB 003.008\n"))
	c.send(req)

	events := finishRFB(t, hp, done).decoded.([]parsedRFB)
	require.Equal(t, []parsedRFB{
		{Direction: "write", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "read", Payload: req},
	}, events)
}

func TestHandleRFBEarlyDisconnect(t *testing.T) {
	c, hp, done := startRFB(t)

	c.expect([]byte("RFB 003.008\n"))
	c.send([]byte("RFB 00"))
	require.NoError(t, c.conn.Close())

	produced := finishRFB(t, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRFB{
		{Direction: "write", Command: "ProtocolVersion", Version: "3.8", Payload: []byte("RFB 003.008\n")},
		{Direction: "read", Command: "ProtocolVersion", Payload: []byte("RFB 00")},
	}, produced.decoded)
}

func rfbCommands(events []parsedRFB) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Command
	}
	return out
}
