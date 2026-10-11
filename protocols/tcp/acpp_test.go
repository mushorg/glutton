package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/acpp"
	"github.com/stretchr/testify/require"
)

func runACPP(t *testing.T, send func(c net.Conn)) (producedTCP, []byte) {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleACPP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
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

// Captured: Ochi event 94df0a05-65ab-4ef9-900d-9f3be446bbaf (tcp/5009,
// donut.scanf.shodan.io): "acpp" followed by 124 zero bytes.
var acppShodanProbe = append([]byte("acpp"), make([]byte, acpp.HeaderSize-4)...)

// acppRequest builds a well-formed header with a valid checksum.
func acppRequest(cmd uint32, bodySize int32, key byte) []byte {
	raw := make([]byte, acpp.HeaderSize)
	copy(raw, acpp.Magic)
	binary.BigEndian.PutUint32(raw[4:], acpp.Version)
	binary.BigEndian.PutUint32(raw[16:], uint32(bodySize))
	binary.BigEndian.PutUint32(raw[20:], 4)
	binary.BigEndian.PutUint32(raw[28:], cmd)
	raw[48] = key
	binary.BigEndian.PutUint32(raw[8:], acpp.Checksum(raw))
	return raw
}

func readACPPReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	reply := make([]byte, acpp.HeaderSize)
	_, err := io.ReadFull(c, reply)
	require.NoError(t, err)
	return reply
}

func TestHandleACPPShodanProbe(t *testing.T) {
	var reply []byte
	produced, resp := runACPP(t, func(c net.Conn) {
		_, err := c.Write(acppShodanProbe)
		require.NoError(t, err)
		reply = readACPPReply(t, c)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, acpp.BuildReply(0, acpp.ErrVersion), reply)
	require.Equal(t, "acpp", produced.protocol)
	require.Equal(t, acppShodanProbe, produced.payload)
	require.Equal(t, []parsedACPP{
		{Direction: "read", Command: "unknown", Version: "0x00000000", Payload: acppShodanProbe},
		{Direction: "write", Command: "unknown", Status: "version", ErrorCode: acpp.ErrVersion, Payload: reply},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleACPPGetpropWithBody(t *testing.T) {
	body := []byte("syNm\x00\x00\x00\x00\x00\x00\x00\x00")
	req := append(acppRequest(0x14, int32(len(body)), 0x5a), body...)
	var reply []byte
	produced, _ := runACPP(t, func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		reply = readACPPReply(t, c)
		require.NoError(t, c.Close())
	})
	key := "5a" + strings.Repeat("00", 31)
	require.Equal(t, []parsedACPP{
		{Direction: "read", Command: "getprop", Version: "0x00030001", Flags: 4, BodySize: int32(len(body)), Key: key, Payload: req},
		{Direction: "write", Command: "getprop", Status: "authentication", ErrorCode: acpp.ErrAuthentication, Payload: reply},
	}, produced.decoded)
}

func TestHandleACPPBadChecksumAndUnknown(t *testing.T) {
	bad := acppRequest(0x1a, -1, 0)
	bad[8] ^= 0xff
	unknown := acppRequest(0x99, -1, 0)
	produced, _ := runACPP(t, func(c net.Conn) {
		for _, req := range [][]byte{bad, unknown} {
			_, err := c.Write(req)
			require.NoError(t, err)
			readACPPReply(t, c)
		}
		require.NoError(t, c.Close())
	})
	events := produced.decoded.([]parsedACPP)
	require.Len(t, events, 4)
	require.True(t, events[0].BadChecksum)
	require.Equal(t, "auth", events[0].Command)
	require.Equal(t, "checksum", events[1].Status)
	require.Equal(t, int32(-1), events[2].BodySize)
	require.Equal(t, "unsupported", events[3].Status)
}

func TestHandleACPPMaxMessages(t *testing.T) {
	produced, _ := runACPP(t, func(c net.Conn) {
		for i := 0; i < maxACPPMessages; i++ {
			_, err := c.Write(acppRequest(0x1b, -1, 0))
			require.NoError(t, err)
			readACPPReply(t, c)
		}
	})
	require.Len(t, produced.decoded.([]parsedACPP), 2*maxACPPMessages)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}

func TestHandleACPPNotACPP(t *testing.T) {
	data := make([]byte, acpp.HeaderSize)
	copy(data, "GET / HTTP/1.0\r\n\r\n")
	produced, resp := runACPP(t, func(c net.Conn) {
		_, err := c.Write(data)
		require.NoError(t, err)
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedACPP{{Direction: "read", Payload: data}}, produced.decoded)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleACPPShortHeader(t *testing.T) {
	produced, resp := runACPP(t, func(c net.Conn) {
		_, err := c.Write([]byte("acpp\x00\x03"))
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, []parsedACPP{{Direction: "read", Payload: []byte("acpp\x00\x03")}}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleACPPEarlyDisconnect(t *testing.T) {
	produced, resp := runACPP(t, func(c net.Conn) {
		require.NoError(t, c.Close())
	})
	require.Empty(t, resp)
	require.Equal(t, "acpp", produced.protocol)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleACPPOversizeBody(t *testing.T) {
	req := acppRequest(0x03, acpp.MaxBody+100, 0)
	produced, _ := runACPP(t, func(c net.Conn) {
		// net.Pipe blocks until the peer reads, so send off-thread; the
		// handler stops reading at the cap.
		go func() {
			_, _ = c.Write(req)
			_, _ = c.Write(make([]byte, acpp.MaxBody+100))
		}()
		readACPPReply(t, c)
	})
	events := produced.decoded.([]parsedACPP)
	require.Len(t, events, 2)
	require.True(t, events[0].Truncated)
	require.Equal(t, "flash_primary", events[0].Command)
	require.Len(t, events[0].Payload, acpp.HeaderSize+acpp.MaxBody)
	require.Equal(t, "authentication", events[1].Status)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}
