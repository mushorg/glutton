package tcp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func runDNS(t *testing.T, send func(c net.Conn)) producedTCP {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleDNS(context.Background(), serverConn, connection.Metadata{TargetPort: 53}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	send(client)
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
	return produced
}

func dnsFrame(t *testing.T, msgHex string) []byte {
	t.Helper()
	msg, err := hex.DecodeString(msgHex)
	require.NoError(t, err)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

func readDNSReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var prefix [2]byte
	_, err := io.ReadFull(c, prefix[:])
	require.NoError(t, err)
	reply := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	_, err = io.ReadFull(c, reply)
	require.NoError(t, err)
	return append(prefix[:], reply...)
}

// Captured: Ochi tcp/53 event from infrawatch (69.5.169[.]144), 2026-10-22
// 21:43:27 UTC, cloudflare.com A with EDNS0, which the catch-all answered
// with random bytes.
const infrawatchDNS = "002bf50f010000010000000000010a636c6f7564666c61726503636f6d000001000100002904d0000000000000"

func TestHandleDNSQuery(t *testing.T) {
	query := dnsFrame(t, infrawatchDNS[4:])
	require.Equal(t, infrawatchDNS, hex.EncodeToString(query))
	var reply []byte
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(query)
		require.NoError(t, err)
		reply = readDNSReply(t, c)
		require.NoError(t, c.Close())
	})
	require.Equal(t, "002bf50f810500010000000000010a636c6f7564666c61726503636f6d000001000100002904d0000000000000", hex.EncodeToString(reply))
	require.LessOrEqual(t, len(reply), len(query))
	require.Equal(t, "dns", produced.protocol)
	require.Equal(t, query, produced.payload)
	require.Equal(t, []parsedDNS{
		{Direction: "read", ID: 0xf50f, Command: "A", Path: "cloudflare.com", Payload: query},
		{Direction: "write", ID: 0xf50f, Status: "REFUSED", Payload: reply},
	}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleDNSAXFRAndChaos(t *testing.T) {
	axfr := dnsFrame(t, "123400000001000000000000"+"076578616d706c65036f726700"+"00fc0001")
	chaos := dnsFrame(t, "abcd010000010000000000000776657273696f6e0462696e6400"+"0010"+"0003")
	produced := runDNS(t, func(c net.Conn) {
		for _, q := range [][]byte{axfr, chaos} {
			_, err := c.Write(q)
			require.NoError(t, err)
			require.Equal(t, byte(5), readDNSReply(t, c)[5]&0x0f)
		}
		require.NoError(t, c.Close())
	})
	events := produced.decoded.([]parsedDNS)
	require.Len(t, events, 4)
	require.Equal(t, "AXFR", events[0].Command)
	require.Equal(t, "example.org", events[0].Path)
	require.Empty(t, events[0].Class)
	require.Equal(t, "TXT", events[2].Command)
	require.Equal(t, "version.bind", events[2].Path)
	require.Equal(t, "CH", events[2].Class)
	require.Equal(t, "REFUSED", events[3].Status)
}

func TestHandleDNSNotImplementedOpcode(t *testing.T) {
	// UPDATE (opcode 5) for example.org SOA
	update := dnsFrame(t, "999928000001000000000000"+"076578616d706c65036f726700"+"00060001")
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(update)
		require.NoError(t, err)
		require.Equal(t, byte(4), readDNSReply(t, c)[5]&0x0f)
		require.NoError(t, c.Close())
	})
	events := produced.decoded.([]parsedDNS)
	require.Equal(t, "update", events[0].Opcode)
	require.Equal(t, "NOTIMP", events[1].Status)
}

func TestHandleDNSFormErr(t *testing.T) {
	// QDCOUNT 1 with no question after the header
	bad := dnsFrame(t, "abcd01000001000000000000")
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(bad)
		require.NoError(t, err)
		reply := readDNSReply(t, c)
		require.Equal(t, "000c"+"abcd8101"+"00000000"+"00000000", hex.EncodeToString(reply))
		require.NoError(t, c.Close())
	})
	events := produced.decoded.([]parsedDNS)
	require.Equal(t, parsedDNS{Direction: "read", ID: 0xabcd, Payload: bad}, events[0])
	require.Equal(t, "FORMERR", events[1].Status)
}

func TestHandleDNSIgnoresResponses(t *testing.T) {
	msg := dnsFrame(t, infrawatchDNS[4:])
	msg[4] |= 0x80 // QR
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(msg)
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	events := produced.decoded.([]parsedDNS)
	require.Len(t, events, 1, "no reply to a response")
	require.Equal(t, "read", events[0].Direction)
}

func TestHandleDNSShortAndEarlyDisconnect(t *testing.T) {
	// 5-byte message: no header, no reply, connection closed
	short := []byte{0, 5, 1, 2, 3, 4, 5}
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(short)
		require.NoError(t, err)
		_, err = io.ReadAll(c)
		require.NoError(t, err)
	})
	require.Equal(t, []parsedDNS{{Direction: "read", Payload: short}}, produced.decoded)

	// connect and leave
	produced = runDNS(t, func(c net.Conn) { require.NoError(t, c.Close()) })
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleDNSTruncatedBody(t *testing.T) {
	// A plain HTTP request is read as a 0x4745 (18245) byte "message"; the
	// bytes that did arrive are still captured.
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	produced := runDNS(t, func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Equal(t, req, produced.payload)
	require.Equal(t, []parsedDNS{{Direction: "read", Payload: req, Truncated: true}}, produced.decoded)
	require.Equal(t, connection.EndReadError, produced.endReason)
}

func TestHandleDNSMaxMessages(t *testing.T) {
	query := dnsFrame(t, infrawatchDNS[4:])
	produced := runDNS(t, func(c net.Conn) {
		for i := 0; i < maxDNSMessages; i++ {
			_, err := c.Write(query)
			require.NoError(t, err)
			readDNSReply(t, c)
		}
	})
	require.Len(t, produced.decoded.([]parsedDNS), 2*maxDNSMessages)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}
