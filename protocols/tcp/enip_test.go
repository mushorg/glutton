package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/enip"
	"github.com/stretchr/testify/require"
)

// enipCensysListIdentity is the read frame of Ochi event
// e5ed3dc4-7163-46f6-b370-3ca529d487de (Censys, sender context "OISYSNEC").
var enipCensysListIdentity = []byte{
	0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x49, 0x53, 0x59,
	0x53, 0x4e, 0x45, 0x43, 0x00, 0x00, 0x00, 0x00,
}

const enipCensysContext = "4f495359534e4543"

// localAddrConn reports a fixed local address, as an accepted TCP conn does.
type localAddrConn struct {
	net.Conn
	local net.Addr
}

func (c localAddrConn) LocalAddr() net.Addr { return c.local }

func enipRequest(cmd uint16, session uint32, body []byte) []byte {
	return enip.Header{Command: cmd, SessionHandle: session, SenderContext: [8]byte{'c', 't', 'x'}}.Marshal(body)
}

func startENIP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	serial, handle := enipSerial, enipSessionHandle
	enipSerial = func() uint32 { return 0x11223344 }
	enipSessionHandle = func() uint32 { return 0xdeadbeef }
	t.Cleanup(func() { enipSerial, enipSessionHandle = serial, handle })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	conn := localAddrConn{Conn: serverConn, local: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 44818}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleENIP(context.Background(), conn, connection.Metadata{TargetPort: 44818}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return client, hp, done
}

func waitENIPEvent(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	require.NoError(t, <-done)
	select {
	case ev := <-hp.produced:
		require.Equal(t, "enip", ev.protocol)
		require.Empty(t, hp.produced, "expected exactly one produced event")
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced EtherNet/IP event")
		return producedTCP{}
	}
}

func readENIPReply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	b := make([]byte, enip.HeaderSize)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	hdr, err := enip.ParseHeader(b)
	require.NoError(t, err)
	body := make([]byte, hdr.Length)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)
	return append(b, body...)
}

func TestHandleENIPCensysListIdentity(t *testing.T) {
	client, hp, done := startENIP(t)

	_, err := client.Write(enipCensysListIdentity)
	require.NoError(t, err)
	reply := readENIPReply(t, client)
	require.NoError(t, client.Close())

	req, _ := enip.ParseHeader(enipCensysListIdentity)
	id := enip.DefaultIdentity
	id.SerialNumber = 0x11223344
	require.Equal(t, enip.ListIdentityReply(req, id, net.IPv4(10, 0, 0, 5), 44818), reply)

	ev := waitENIPEvent(t, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedENIP{
		{Direction: "read", Command: "ListIdentity", SenderContext: enipCensysContext, Payload: enipCensysListIdentity},
		{
			Direction: "write", Command: "ListIdentity", SenderContext: enipCensysContext, Status: "success",
			// the advertised sensor address is recorded as 1.2.3.4
			Payload: enip.ListIdentityReply(req, id, net.IPv4(1, 2, 3, 4), 44818),
		},
	}, ev.decoded)
}

func TestHandleENIPSession(t *testing.T) {
	client, hp, done := startENIP(t)
	ctx := "6374780000000000"

	steps := []struct {
		req    []byte
		status uint32
		handle uint32
	}{
		{enipRequest(enip.CmdListServices, 0, nil), enip.StatusSuccess, 0},
		{enipRequest(enip.CmdListInterfaces, 0, nil), enip.StatusSuccess, 0},
		{enipRequest(enip.CmdSendRRData, 0, make([]byte, 16)), enip.StatusInvalidSession, 0},
		{enipRequest(enip.CmdRegisterSession, 0, []byte{1, 0, 0, 0}), enip.StatusSuccess, 0xdeadbeef},
		{enipRequest(enip.CmdSendRRData, 0xdeadbeef, make([]byte, 16)), enip.StatusInvalidCommand, 0xdeadbeef},
		{enipRequest(0x1234, 0xdeadbeef, nil), enip.StatusInvalidCommand, 0xdeadbeef},
	}
	var want []parsedENIP
	for _, s := range steps {
		_, err := client.Write(s.req)
		require.NoError(t, err)
		reply := readENIPReply(t, client)
		hdr, _ := enip.ParseHeader(reply)
		require.Equal(t, s.status, hdr.Status)
		require.Equal(t, s.handle, hdr.SessionHandle)
		req, _ := enip.ParseHeader(s.req)
		want = append(want,
			parsedENIP{Direction: "read", Command: enip.CommandName(req.Command), SessionHandle: req.SessionHandle, SenderContext: ctx, Payload: s.req},
			parsedENIP{Direction: "write", Command: enip.CommandName(req.Command), SessionHandle: s.handle, SenderContext: ctx, Status: enip.StatusName(s.status), Payload: reply},
		)
	}
	unreg := enipRequest(enip.CmdUnRegisterSession, 0xdeadbeef, nil)
	_, err := client.Write(unreg)
	require.NoError(t, err)
	want = append(want, parsedENIP{Direction: "read", Command: "UnRegisterSession", SessionHandle: 0xdeadbeef, SenderContext: ctx, Payload: unreg})

	ev := waitENIPEvent(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, want, ev.decoded)
}

func TestHandleENIPEarlyDisconnect(t *testing.T) {
	client, hp, done := startENIP(t)

	_, err := client.Write(enipCensysListIdentity[:10])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	ev := waitENIPEvent(t, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedENIP{
		{Direction: "read", Command: "malformed", Payload: enipCensysListIdentity[:10], Truncated: true},
	}, ev.decoded)
}

func TestHandleENIPOversize(t *testing.T) {
	client, hp, done := startENIP(t)

	req := enipRequest(enip.CmdSendRRData, 0, nil)
	binary.LittleEndian.PutUint16(req[2:4], maxENIPBody+1)
	_, err := client.Write(req)
	require.NoError(t, err)
	reply := readENIPReply(t, client)
	hdr, _ := enip.ParseHeader(reply)
	require.Equal(t, uint32(enip.StatusInvalidLength), hdr.Status)

	ev := waitENIPEvent(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedENIP{
		{Direction: "read", Command: "SendRRData", SenderContext: "6374780000000000", Payload: req, Truncated: true},
		{Direction: "write", Command: "SendRRData", SenderContext: "6374780000000000", Status: "invalid_length", Payload: reply},
	}, ev.decoded)
}

func TestHandleENIPMaxRequests(t *testing.T) {
	client, hp, done := startENIP(t)

	// NOP has no reply, so the client can send the whole budget unanswered.
	nop := enipRequest(enip.CmdNOP, 0, nil)
	for range maxENIPRequests {
		_, err := client.Write(nop)
		require.NoError(t, err)
	}

	ev := waitENIPEvent(t, hp, done)
	require.Equal(t, connection.EndMaxFrames, ev.endReason)
	require.Len(t, ev.decoded, maxENIPRequests)
}
