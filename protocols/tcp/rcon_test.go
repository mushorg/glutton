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
	"github.com/mushorg/glutton/protocols/tcp/rcon"
	"github.com/stretchr/testify/require"
)

func runRCON(t *testing.T, send func(c net.Conn)) (producedTCP, []byte) {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRCON(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	send(client)
	resp, _ := io.ReadAll(client)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	return produced, resp
}

// Captured: Ochi live stream 2026-10-22 22:03:00 UTC, tcp/27015 from
// butter.scanf.shodan.io: SERVERDATA_AUTH id 0x282, password "test", with a
// size field of 10 although 14 bytes follow.
var rconShodanAuth = []byte("\x0a\x00\x00\x00\x82\x02\x00\x00\x03\x00\x00\x00test\x00\x00")

func readRCONAuthFailure(t *testing.T, c net.Conn) []byte {
	t.Helper()
	reply := make([]byte, 28)
	_, err := io.ReadFull(c, reply)
	require.NoError(t, err)
	return reply
}

func TestHandleRCONShodanAuth(t *testing.T) {
	var reply []byte
	produced, resp := runRCON(t, func(c net.Conn) {
		_, err := c.Write(rconShodanAuth)
		require.NoError(t, err)
		reply = readRCONAuthFailure(t, c)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, rcon.BuildAuthFailure(0x282), reply)
	require.Equal(t, "rcon", produced.protocol)
	require.Equal(t, rconShodanAuth, produced.payload)
	require.Equal(t, []parsedRCON{
		{Direction: "read", Command: "auth", RequestID: ptrInt32(0x282), Size: 10, SizeMismatch: true, Password: "test", Payload: rconShodanAuth},
		{Direction: "write", Command: "auth", RequestID: ptrInt32(-1), Status: "auth-failed", Payload: reply},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRCONGuessesThenExec(t *testing.T) {
	first := rcon.BuildPacket(1, rcon.TypeAuth, "admin")
	second := rcon.BuildPacket(2, rcon.TypeAuth, "")
	exec := rcon.BuildPacket(3, rcon.TypeExecCommand, "status")
	produced, resp := runRCON(t, func(c net.Conn) {
		for _, pkt := range [][]byte{first, second} {
			_, err := c.Write(pkt)
			require.NoError(t, err)
			readRCONAuthFailure(t, c)
		}
		_, err := c.Write(exec)
		require.NoError(t, err)
	})
	require.Empty(t, resp)
	events := produced.decoded.([]parsedRCON)
	require.Len(t, events, 5)
	require.Equal(t, parsedRCON{Direction: "read", Command: "auth", RequestID: ptrInt32(1), Size: 15, Password: "admin", Payload: first}, events[0])
	require.Equal(t, parsedRCON{Direction: "read", Command: "auth", RequestID: ptrInt32(2), Size: 10, Payload: second}, events[2])
	require.Equal(t, "auth-failed", events[3].Status)
	require.Equal(t, parsedRCON{Direction: "read", Command: "exec", RequestID: ptrInt32(3), Size: 16, Body: "status", Payload: exec}, events[4])
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleRCONResponseValueIgnored(t *testing.T) {
	// Some clients send an empty RESPONSE_VALUE after a command to mark the
	// end of a multi-packet reply; it gets no answer.
	empty := rcon.BuildPacket(9, rcon.TypeResponseValue, "")
	produced, resp := runRCON(t, func(c net.Conn) {
		_, err := c.Write(empty)
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedRCON{
		{Direction: "read", Command: "response", RequestID: ptrInt32(9), Size: 10, Payload: empty},
	}, produced.decoded)
}

func TestHandleRCONMaxPackets(t *testing.T) {
	pkt := rcon.BuildPacket(1, rcon.TypeAuth, "x")
	produced, _ := runRCON(t, func(c net.Conn) {
		for i := 0; i < maxRCONPackets; i++ {
			_, err := c.Write(pkt)
			require.NoError(t, err)
			readRCONAuthFailure(t, c)
		}
	})
	require.Len(t, produced.decoded.([]parsedRCON), 2*maxRCONPackets)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}

func TestHandleRCONNotRCON(t *testing.T) {
	data := []byte("GET / HTTP/1.0\r\n\r\n")
	produced, resp := runRCON(t, func(c net.Conn) {
		_, err := c.Write(data)
		require.NoError(t, err)
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedRCON{{Direction: "read", Payload: data[:rcon.HeaderSize]}}, produced.decoded)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleRCONShortHeader(t *testing.T) {
	produced, resp := runRCON(t, func(c net.Conn) {
		_, err := c.Write(rconShodanAuth[:6])
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedRCON{{Direction: "read", Payload: rconShodanAuth[:6]}}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRCONUnterminatedBody(t *testing.T) {
	data := rconShodanAuth[:14]
	produced, resp := runRCON(t, func(c net.Conn) {
		_, err := c.Write(data)
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedRCON{
		{Direction: "read", Command: "auth", RequestID: ptrInt32(0x282), Size: 10, Password: "te", Payload: data},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRCONEarlyDisconnect(t *testing.T) {
	produced, resp := runRCON(t, func(c net.Conn) {
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, "rcon", produced.protocol)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRCONOversizeBody(t *testing.T) {
	hdr := rcon.BuildPacket(5, rcon.TypeExecCommand, "")[:rcon.HeaderSize]
	long := bytes.Repeat([]byte("A"), rcon.MaxBody+100)
	produced, resp := runRCON(t, func(c net.Conn) {
		// net.Pipe blocks until the peer reads, so send off-thread; the
		// handler stops reading at the cap.
		go func() {
			_, _ = c.Write(hdr)
			_, _ = c.Write(long)
		}()
	})
	require.Empty(t, resp)
	events := produced.decoded.([]parsedRCON)
	require.Len(t, events, 1)
	require.True(t, events[0].Truncated)
	require.False(t, events[0].SizeMismatch)
	require.Equal(t, strings.Repeat("A", rcon.MaxBody), events[0].Body)
	require.Len(t, events[0].Payload, rcon.HeaderSize+rcon.MaxBody)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}
