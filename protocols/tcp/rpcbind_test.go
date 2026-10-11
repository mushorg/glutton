package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/stretchr/testify/require"
)

// read frame 1 (44 bytes): Shodan PMAPPROC_DUMP, Ochi event c6b98aad-61b0-4449-ac2c-88d5cdd4b111
var rpcbindRead1 = []byte{
	0x80, 0x00, 0x00, 0x28, 0xe8, 0x77, 0xbb, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func rpcWords(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return b
}

func startRPCBind(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRPCBind(context.Background(), serverConn, connection.Metadata{TargetPort: 111, TargetIP: "198.51.100.1"}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func readRPCReply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 4)
	_, err := io.ReadFull(conn, hdr)
	require.NoError(t, err)
	mark := binary.BigEndian.Uint32(hdr)
	require.NotZero(t, mark&0x80000000, "last fragment")
	body := make([]byte, mark&0x7fffffff)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)
	return append(hdr, body...)
}

func waitRPCBind(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "rpcbind", produced.protocol)
	return produced, err
}

func TestHandleRPCBindShodanDump(t *testing.T) {
	client, hp, done := startRPCBind(t)

	_, err := client.Write(rpcbindRead1)
	require.NoError(t, err)
	reply := readRPCReply(t, client)
	require.Equal(t, rpcWords(0xe877bb11, 1, 0, 0, 0, 0), reply[4:28], "echoed XID, accepted, SUCCESS")

	// pmaplist: 8 entries of {1, prog, vers, prot, port} then 0.
	list := reply[28:]
	require.Len(t, list, 8*20+4)
	require.Equal(t, rpcWords(1, 100000, 4, 6, 111), list[:20])
	require.Equal(t, rpcWords(0), list[len(list)-4:])
	statd := oncrpc.Mappings([]byte("198.51.100.1"))[6]
	require.Equal(t, rpcWords(1, 100024, 1, 17, uint32(statd.Port)), list[120:140])

	require.NoError(t, client.Close())
	produced, err := waitRPCBind(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, rpcbindRead1, produced.payload)
	require.Equal(t, []parsedRPCBind{
		{Direction: "read", Command: "PMAPPROC_DUMP", XID: 0xe877bb11, Program: 100000, Version: 2, Procedure: 4, Auth: "AUTH_NONE", Payload: rpcbindRead1},
		{Direction: "write", Command: "PMAPPROC_DUMP", XID: 0xe877bb11, Status: "SUCCESS", Payload: reply},
	}, produced.decoded)
}

func TestHandleRPCBindGetPortThenNFS(t *testing.T) {
	client, hp, done := startRPCBind(t)

	cred := append(rpcWords(0x6000), []byte{0, 0, 0, 4, 'k', 'a', 'l', 'i'}...)
	cred = append(cred, rpcWords(0, 0, 0)...)
	getport := append(rpcWords(7, 0, 2, 100000, 2, 3, 1, uint32(len(cred))), cred...)
	getport = append(getport, rpcWords(0, 0, 100005, 3, 6, 0)...)
	getportWire := oncrpc.Frame(getport)
	_, err := client.Write(getportWire)
	require.NoError(t, err)
	first := readRPCReply(t, client)
	require.Equal(t, rpcWords(7, 1, 0, 0, 0, 0, 0), first[4:], "mountd not registered: port 0")

	nfs := oncrpc.Frame(rpcWords(8, 0, 2, 100003, 3, 0, 0, 0, 0, 0))
	_, err = client.Write(nfs)
	require.NoError(t, err)
	second := readRPCReply(t, client)
	require.Equal(t, rpcWords(8, 1, 0, 0, 0, 1), second[4:])

	require.NoError(t, client.Close())
	produced, err := waitRPCBind(t, hp, done)
	require.NoError(t, err)
	zero := uint32(0)
	require.Equal(t, []parsedRPCBind{
		{Direction: "read", Command: "PMAPPROC_GETPORT", XID: 7, Program: 100000, Version: 2, Procedure: 3, Auth: "AUTH_SYS", MachineName: "kali", UID: &zero, GID: &zero, TargetProgram: 100005, TargetVersion: 3, Netid: "tcp", Payload: getportWire},
		{Direction: "write", Command: "PMAPPROC_GETPORT", XID: 7, Status: "SUCCESS", Payload: first},
		{Direction: "read", Command: "CALL", XID: 8, Program: 100003, Version: 3, Auth: "AUTH_NONE", Payload: nfs},
		{Direction: "write", Command: "CALL", XID: 8, Status: "PROG_UNAVAIL", Payload: second},
	}, produced.decoded)
}

func TestHandleRPCBindEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startRPCBind(t)
	require.NoError(t, client.Close())

	produced, err := waitRPCBind(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRPCBindPartialRecordStored(t *testing.T) {
	client, hp, done := startRPCBind(t)
	partial := rpcbindRead1[:20]
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitRPCBind(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRPCBind{{Direction: "read", Command: "UNKNOWN", Payload: partial}}, produced.decoded)
}

func TestHandleRPCBindMalformedCall(t *testing.T) {
	client, hp, done := startRPCBind(t)
	junk := oncrpc.Frame([]byte("not an rpc call at all, but framed"))
	_, err := client.Write(junk)
	require.NoError(t, err)

	produced, err := waitRPCBind(t, hp, done)
	require.ErrorIs(t, err, oncrpc.ErrMalformed)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedRPCBind{{Direction: "read", Command: "UNKNOWN", Payload: junk}}, produced.decoded)
}

func TestHandleRPCBindOversizeRecordTruncated(t *testing.T) {
	client, hp, done := startRPCBind(t)
	big := append(rpcWords(0x80000000|(rpcbindMaxRecord+100)), bytes.Repeat([]byte{0x41}, rpcbindMaxRecord+100)...)
	go func() { _, _ = client.Write(big) }()

	produced, err := waitRPCBind(t, hp, done)
	require.ErrorIs(t, err, oncrpc.ErrRecordTooLarge)
	frames := produced.decoded.([]parsedRPCBind)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Len(t, frames[0].Payload, rpcbindMaxRecord+4)
}
