package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/stretchr/testify/require"
)

// read frame (44 bytes): NFS NULL with a bogus version (version probe),
// Ochi event d33b1b2d-9db3-4808-b558-ef773e6d207b
var nfsProbe = []byte{
	0x80, 0x00, 0x00, 0x28, 0x03, 0x8d, 0x42, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x01, 0x86, 0xa3, 0x05, 0x4d, 0x88, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func nfsCall(xid, vers, proc uint32, args ...uint32) []byte {
	body := rpcWords(xid, 0, 2, oncrpc.ProgNFS, vers, proc, 0, 0, 0, 0)
	body = append(body, rpcWords(args...)...)
	return oncrpc.Frame(body)
}

func startNFS(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleNFS(context.Background(), serverConn, connection.Metadata{TargetPort: 2049}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitNFS(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "nfs", produced.protocol)
	return produced, err
}

func TestHandleNFSVersionProbe(t *testing.T) {
	client, hp, done := startNFS(t)
	_, err := client.Write(nfsProbe)
	require.NoError(t, err)
	reply := readRPCReply(t, client)
	// accepted, AUTH_NONE verifier, PROG_MISMATCH, low 3, high 4
	require.Equal(t, rpcWords(0x038d4260, 1, 0, 0, 0, 2, 3, 4), reply[4:])
	client.Close()

	produced, err := waitNFS(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, nfsProbe, produced.payload)
	frames, ok := produced.decoded.([]parsedNFS)
	require.True(t, ok)
	require.Equal(t, []parsedNFS{
		{Direction: "read", Command: "NFSPROC_0", XID: 0x038d4260, Program: oncrpc.ProgNFS, Version: 0x054d8849, Auth: "AUTH_NONE", Payload: nfsProbe},
		{Direction: "write", Command: "NFSPROC_0", XID: 0x038d4260, Status: "PROG_MISMATCH", Payload: reply},
	}, frames)
}

func TestHandleNFSNullAndFileOps(t *testing.T) {
	client, hp, done := startNFS(t)

	_, err := client.Write(nfsCall(1, 3, 0))
	require.NoError(t, err)
	require.Equal(t, rpcWords(1, 1, 0, 0, 0, 0), readRPCReply(t, client)[4:], "v3 NULL succeeds")

	_, err = client.Write(nfsCall(2, 3, 19, 0))
	require.NoError(t, err)
	require.Equal(t, rpcWords(2, 1, 0, 0, 0, 0, 10001, 0), readRPCReply(t, client)[4:], "v3 FSINFO fails with BADHANDLE")

	// v4 COMPOUND, empty tag, minor 0, 1 op
	_, err = client.Write(nfsCall(3, 4, 1, 0, 0, 1))
	require.NoError(t, err)
	require.Equal(t, rpcWords(3, 1, 0, 0, 0, 0, 13, 0, 0), readRPCReply(t, client)[4:], "v4 COMPOUND denied")

	_, err = client.Write(nfsCall(4, 3, 6))
	require.NoError(t, err)
	require.Equal(t, rpcWords(4, 1, 0, 0, 0, 3), readRPCReply(t, client)[4:], "v3 READ is PROC_UNAVAIL")
	client.Close()

	produced, err := waitNFS(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedNFS)
	require.Len(t, frames, 8)
	require.Equal(t, "NFSPROC3_NULL", frames[0].Command)
	require.Equal(t, "NFSPROC3_FSINFO", frames[2].Command)
	require.Equal(t, "NFSPROC4_COMPOUND", frames[4].Command)
	require.Equal(t, uint32(0), *frames[4].MinorVer)
	require.Equal(t, uint32(1), *frames[4].Ops)
	require.Equal(t, "PROC_UNAVAIL", frames[7].Status)
}

func TestHandleNFSOtherProgram(t *testing.T) {
	client, hp, done := startNFS(t)
	_, err := client.Write(oncrpc.Frame(rpcWords(9, 0, 2, 100005, 3, 0, 0, 0, 0, 0)))
	require.NoError(t, err)
	require.Equal(t, rpcWords(9, 1, 0, 0, 0, 1), readRPCReply(t, client)[4:])
	client.Close()
	produced, _ := waitNFS(t, hp, done)
	require.Equal(t, "PROG_UNAVAIL", produced.decoded.([]parsedNFS)[1].Status)
}

func TestHandleNFSEarlyDisconnect(t *testing.T) {
	client, hp, done := startNFS(t)
	client.Close()
	produced, err := waitNFS(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded.([]parsedNFS))
}

func TestHandleNFSMalformed(t *testing.T) {
	client, hp, done := startNFS(t)
	// last fragment of 8 bytes: too short for an RPC call
	go func() { _, _ = client.Write(append(rpcWords(0x80000008), rpcWords(1, 0)...)) }()
	produced, err := waitNFS(t, hp, done)
	require.Error(t, err)
	frames := produced.decoded.([]parsedNFS)
	require.Len(t, frames, 1)
	require.Equal(t, "UNKNOWN", frames[0].Command)
}
