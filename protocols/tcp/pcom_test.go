package tcp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/pcom"
	"github.com/stretchr/testify/require"
)

// The requests mirror two captures on tcp/20256 (Ochi events
// e5e87010-e004-4784-977d-5b6afc6fddd8, unit 40, and
// db359b9c-00ad-4914-adfc-c15a8d34922a, unit " 1"); replies are synthetic.

var (
	pcomTestIdentity = pcom.Identity{ModelCode: "070500", Hardware: 'B', OSMajor: 4, OSMinor: 1, OSBuild: 7}

	pcomIDReq     = []byte("SIe\x00\x08\x00/40IDF1\r")
	pcomUGReq     = []byte("IUe\x00\x08\x00/ 1UGED\r")
	pcomRNReq     = []byte("IUe\x00\x0f\x00/40RNJ00090178\r")
	pcomBinaryReq = []byte("WIf\x00\x1b\x00/_OPLC\x00\xfe\x01\x01\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\xfd\x00\x00\x5c")
)

func runPCOM(t *testing.T, client func(c net.Conn)) producedTCP {
	t.Helper()
	prev := pcomIdentity
	pcomIdentity = func() pcom.Identity { return pcomTestIdentity }
	t.Cleanup(func() { pcomIdentity = prev })

	pipe, cli := net.Pipe()
	h := newFakeHoneypot()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = HandlePCOM(context.Background(), pipe, connection.Metadata{TargetPort: 20256}, &recordingLogger{}, h)
	}()
	require.NoError(t, cli.SetDeadline(time.Now().Add(2*time.Second)))
	client(cli)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	require.Len(t, h.produced, 1)
	ev := <-h.produced
	require.Equal(t, "pcom", ev.protocol)
	return ev
}

// pcomExchange sends req and returns the reply frame.
func pcomExchange(t *testing.T, c net.Conn, req []byte) (pcom.Header, []byte, []byte) {
	t.Helper()
	_, err := c.Write(req)
	require.NoError(t, err)
	hdr, msg, raw, err := pcom.ReadFrame(c)
	require.NoError(t, err)
	return hdr, msg, raw
}

func TestPCOMCapturedSession(t *testing.T) {
	var idReply, ugReply, rnReply, binReply []byte
	ev := runPCOM(t, func(c net.Conn) {
		_, msg, raw := pcomExchange(t, c, pcomIDReq)
		idReply = raw
		require.Equal(t, string(pcom.IDReply("40", pcomTestIdentity)), string(msg))
		_, _, ugReply = pcomExchange(t, c, pcomUGReq)
		_, _, rnReply = pcomExchange(t, c, pcomRNReq)
		hdr, msg, raw := pcomExchange(t, c, pcomBinaryReq)
		binReply = raw
		require.Equal(t, pcom.Header{TID: 0x4957, Mode: pcom.ModeBinary, Length: 27}, hdr)
		require.Equal(t, pcomBinaryReq[pcom.HeaderLen:], msg)
	})

	require.Equal(t, pcomIDReq, ev.payload)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedPCOM{
		{Direction: "read", Mode: "ascii", TID: 0x4953, Unit: "40", Command: "ID", Payload: pcomIDReq},
		{Direction: "write", Mode: "ascii", TID: 0x4953, Unit: "40", Command: "ID", Status: "id", Payload: idReply},
		{Direction: "read", Mode: "ascii", TID: 0x5549, Unit: " 1", Command: "UG", Payload: pcomUGReq},
		{Direction: "write", Mode: "ascii", TID: 0x5549, Unit: " 1", Command: "UG", Status: "error", Payload: ugReply},
		{Direction: "read", Mode: "ascii", TID: 0x5549, Unit: "40", Command: "RN", Payload: pcomRNReq},
		{Direction: "write", Mode: "ascii", TID: 0x5549, Unit: "40", Command: "RN", Status: "error", Payload: rnReply},
		{Direction: "read", Mode: "binary", TID: 0x4957, Unit: "0", Command: "0x0c", Payload: pcomBinaryReq},
		{Direction: "write", Mode: "binary", TID: 0x4957, Unit: "0", Command: "0x0c", Status: "echo", Payload: binReply},
	}, ev.decoded)
}

func TestPCOMIDReplyIsValid(t *testing.T) {
	runPCOM(t, func(c net.Conn) {
		hdr, msg, _ := pcomExchange(t, c, pcomIDReq)
		require.Equal(t, pcom.Header{TID: 0x4953, Mode: pcom.ModeASCII, Length: uint16(len(msg))}, hdr)
		require.Equal(t, "/A40ID070500B040107", string(msg[:len(msg)-3]))
		req, ok := pcom.ParseASCII(msg)
		require.True(t, ok)
		require.True(t, req.ChecksumOK)
	})
}

func TestPCOMUnknownCommandIsError(t *testing.T) {
	ev := runPCOM(t, func(c net.Conn) {
		_, msg, _ := pcomExchange(t, c, pcomUGReq)
		require.Equal(t, string(pcom.ErrorReply(" 1", pcom.ErrCodeUnrecognized)), string(msg))
	})
	frames := ev.decoded.([]parsedPCOM)
	require.Len(t, frames, 2)
	require.Equal(t, "error", frames[1].Status)
}

func TestPCOMMalformedASCIIBodyGetsError(t *testing.T) {
	ev := runPCOM(t, func(c net.Conn) {
		_, msg, _ := pcomExchange(t, c, []byte("AAe\x00\x03\x00GET"))
		require.Equal(t, string(pcom.ErrorReply("00", pcom.ErrCodeUnrecognized)), string(msg))
	})
	frames := ev.decoded.([]parsedPCOM)
	require.Len(t, frames, 2)
	require.Equal(t, parsedPCOM{Direction: "read", Mode: "ascii", TID: 0x4141, Payload: []byte("AAe\x00\x03\x00GET")}, frames[0])
	require.Equal(t, "error", frames[1].Status)
}

func TestPCOMMalformedBinaryGetsNoReply(t *testing.T) {
	req := []byte("BBf\x00\x05\x00/_OPL")
	ev := runPCOM(t, func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
	})
	require.Equal(t, []parsedPCOM{{Direction: "read", Mode: "binary", TID: 0x4242, Payload: req}}, ev.decoded)
}

func TestPCOMNotPCOMEndsSession(t *testing.T) {
	ev := runPCOM(t, func(c net.Conn) {
		// the handler reads one 6-byte header, then closes
		_, err := c.Write([]byte("GET / "))
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedPCOM{{Direction: "read", Payload: []byte("GET / ")}}, ev.decoded)
}

func TestPCOMOversizeLengthTruncated(t *testing.T) {
	hdr := []byte("XXe\x00\xff\xff")
	ev := runPCOM(t, func(c net.Conn) {
		_, err := c.Write(hdr)
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedPCOM{{Direction: "read", Payload: hdr, Truncated: true}}, ev.decoded)
}

func TestPCOMEarlyDisconnectMidFrame(t *testing.T) {
	part := pcomIDReq[:9]
	ev := runPCOM(t, func(c net.Conn) {
		_, err := c.Write(part)
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedPCOM{{Direction: "read", Payload: part}}, ev.decoded)
}

func TestPCOMConnectOnlyStillProduces(t *testing.T) {
	ev := runPCOM(t, func(c net.Conn) {})
	require.Empty(t, ev.payload)
	require.Empty(t, ev.decoded)
}

func TestPCOMMaxFrames(t *testing.T) {
	ev := runPCOM(t, func(c net.Conn) {
		for i := 0; i < maxPCOMFrames; i++ {
			pcomExchange(t, c, pcomIDReq)
		}
	})
	require.Equal(t, connection.EndMaxFrames, ev.endReason)
	require.Len(t, ev.decoded.([]parsedPCOM), 2*maxPCOMFrames)
	require.True(t, bytes.Equal(ev.payload, pcomIDReq))
}
