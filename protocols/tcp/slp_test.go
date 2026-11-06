package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Shodan DAAdvert probe captured on tcp/427 (run-1793999100-4 event #7). The
// sensor address was scrubbed to 1.2.3.4 without fixing the length fields, so
// the header announces 61 bytes but only 53 arrive.
var slpCapturedDAAdvert = []byte{
	0x02, 0x08, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x65, 0x6e,
	0x00, 0x00, 0x6a, 0xee, 0x41, 0x2b, 0x00, 0x16, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31,
	0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x00, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
}

// slpDAAdvert is the captured probe with the message and URL lengths repaired.
func slpDAAdvert() []byte {
	b := append([]byte(nil), slpCapturedDAAdvert...)
	b[4] = byte(len(b))
	b[23] = byte(len("http://1.2.3.4"))
	return b
}

// Captured infrawatch SrvRqst (udp/427, Ochi event 79c746cf-1e02-4e46-baf8-b4c69438d318).
var slpSrvRqst = []byte{
	0x02, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 0x65, 0x6e,
	0x00, 0x00, 0x00, 0x2a, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x69, 0x77, 0x73, 0x63,
	0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37, 0x35, 0x63, 0x31, 0x65,
	0x35, 0x31, 0x64, 0x2e, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x77, 0x61, 0x74, 0x63, 0x68, 0x00, 0x17,
	0x69, 0x77, 0x73, 0x63, 0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37,
	0x35, 0x63, 0x31, 0x65, 0x35, 0x31, 0x64, 0x00, 0x00, 0x00, 0x00,
}

// SrvRply: length 20, XID echoed, lang "en", SCOPE_NOT_SUPPORTED, no URLs.
var slpSrvRply = []byte{
	0x02, 0x02, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 'e', 'n',
	0x00, 0x04, 0x00, 0x00,
}

func startSLP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleSLP(context.Background(), serverConn, connection.Metadata{TargetPort: 427}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// finishSLP closes the client, waits for the handler and returns its single event.
func finishSLP(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	_ = client.Close()
	require.NoError(t, <-done)
	var ev producedTCP
	select {
	case ev = <-hp.produced:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced SLP event")
	}
	select {
	case extra := <-hp.produced:
		t.Fatalf("unexpected second event: %+v", extra)
	default:
	}
	require.Equal(t, "slp", ev.protocol)
	return ev
}

func TestHandleSLPCapturedDAAdvertCutOff(t *testing.T) {
	client, hp, done := startSLP(t)
	_, err := client.Write(slpCapturedDAAdvert)
	require.NoError(t, err)

	ev := finishSLP(t, client, hp, done)
	// the client closed mid-message (io.ErrUnexpectedEOF)
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, slpCapturedDAAdvert, ev.payload)
	require.Equal(t, []parsedSLP{{
		Direction: "read", Command: "DAAdvert", Payload: slpCapturedDAAdvert, Truncated: true,
	}}, ev.decoded)
}

func TestHandleSLPDAAdvertThenSrvRqst(t *testing.T) {
	client, hp, done := startSLP(t)
	daadvert := slpDAAdvert()
	_, err := client.Write(daadvert)
	require.NoError(t, err)
	// no reply to a DAAdvert: the next bytes on the wire answer the SrvRqst
	_, err = client.Write(slpSrvRqst)
	require.NoError(t, err)
	resp := make([]byte, len(slpSrvRply))
	_, err = client.Read(resp)
	require.NoError(t, err)
	require.Equal(t, slpSrvRply, resp)

	ev := finishSLP(t, client, hp, done)
	require.Equal(t, []parsedSLP{
		{Direction: "read", Command: "DAAdvert", XID: "0x0000", Lang: "en", URL: "http://1.2.3.4", Scope: "DEFAULT", Payload: daadvert},
		{Direction: "read", Command: "SrvRqst", XID: "0xc0e8", Lang: "en",
			ServiceType: "service:iwscan-c60d855275c1e51d.infrawatch", Scope: "iwscan-c60d855275c1e51d", Payload: slpSrvRqst},
		{Direction: "write", Command: "SrvRply", XID: "0xc0e8", Lang: "en", Status: "SCOPE_NOT_SUPPORTED", Payload: slpSrvRply},
	}, ev.decoded)
}

func TestHandleSLPNotSLP(t *testing.T) {
	client, hp, done := startSLP(t)
	_, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.Error(t, err, "handler stops reading after the 5-byte prefix and closes")

	ev := finishSLP(t, client, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedSLP{{Direction: "read", Command: "malformed", Payload: []byte("GET /"), Truncated: true}}, ev.decoded)
}

func TestHandleSLPOversizeLength(t *testing.T) {
	client, hp, done := startSLP(t)
	prefix := []byte{0x02, 0x03, 0x01, 0x00, 0x00} // SrvReg announcing 65536 bytes
	_, err := client.Write(prefix)
	require.NoError(t, err)

	ev := finishSLP(t, client, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedSLP{{Direction: "read", Command: "SrvReg", Payload: prefix, Truncated: true}}, ev.decoded)
}

func TestHandleSLPEarlyDisconnect(t *testing.T) {
	client, hp, done := startSLP(t)
	ev := finishSLP(t, client, hp, done)
	require.Equal(t, []parsedSLP{}, ev.decoded)
	require.Empty(t, ev.payload)
}
