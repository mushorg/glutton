package tcp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/mctp"
	"github.com/stretchr/testify/require"
)

// read frame 1 of mushorg/glutton#73 (tcp/9000)
var mctpIssue73Read1 = []byte("REMOTE HI_SRDK_DEV_GetHddInfo MCTP/1.0\r\nCSeq:173\r\nAccept:text/HDP\r\nContent-Type:text/HDP\r\nFunc-Version:0x10\r\nContent-Length:15\r\n\r\nSegment-Num:0\r\n")

// synthetic follow-up in the Kguard advisory's shape: one 4-byte data segment
var mctpGetUserList = []byte("REMOTE HI_SRDK_SYS_USERMNG_GetUserList MCTP/1.0\r\nCSeq:174\r\nAccept:text/HDP\r\nContent-Type:text/HDP\r\nFunc-Version:0x10\r\nContent-Length:51\r\n\r\nSegment-Num:1\r\nSegment-Seq:1\r\nData-Length:4\r\n\r\n\x00\x00\x00\x01")

func startMCTP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMCTP(context.Background(), serverConn, connection.Metadata{TargetPort: 9000}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func readMCTPReply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return buf[:n]
}

func waitMCTP(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "mctp", produced.protocol)
	return produced, err
}

func TestHandleMCTPSession(t *testing.T) {
	client, hp, done := startMCTP(t)

	_, err := client.Write(mctpIssue73Read1)
	require.NoError(t, err)
	first := readMCTPReply(t, client)
	require.Equal(t, "MCTP/1.0 200 OK\r\nContent-Type:text/HDP\r\nCSeq:173\r\nReturn-Code:0\r\nContent-Length:15\r\n\r\nSegment-Num:0\r\n", string(first))

	_, err = client.Write(mctpGetUserList)
	require.NoError(t, err)
	second := readMCTPReply(t, client)
	require.Equal(t, mctp.BuildResponse("174", 0), second)

	require.NoError(t, client.Close())
	produced, err := waitMCTP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedMCTP{
		{Direction: "read", Command: "HI_SRDK_DEV_GetHddInfo", Method: "REMOTE", CSeq: "173", FuncVersion: "0x10", Payload: mctpIssue73Read1},
		{Direction: "write", CSeq: "173", Status: "200", ReturnCode: "0", Payload: first},
		{Direction: "read", Command: "HI_SRDK_SYS_USERMNG_GetUserList", Method: "REMOTE", CSeq: "174", FuncVersion: "0x10", Segments: 1, Payload: mctpGetUserList},
		{Direction: "write", CSeq: "174", Status: "200", ReturnCode: "0", Payload: second},
	}, produced.decoded)
}

func TestHandleMCTPEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startMCTP(t)
	require.NoError(t, client.Close())

	produced, err := waitMCTP(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleMCTPPartialRequestStored(t *testing.T) {
	client, hp, done := startMCTP(t)
	partial := mctpIssue73Read1[:60]
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitMCTP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedMCTP{{Direction: "read", Command: "HI_SRDK_DEV_GetHddInfo", Method: "REMOTE", CSeq: "173", Payload: partial}}, produced.decoded)
}

func TestHandleMCTPGarbageAfterRequest(t *testing.T) {
	client, hp, done := startMCTP(t)
	_, err := client.Write(mctpIssue73Read1)
	require.NoError(t, err)
	readMCTPReply(t, client)
	_, err = client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)

	produced, err := waitMCTP(t, hp, done)
	require.ErrorIs(t, err, mctp.ErrMalformed)
	require.Equal(t, connection.EndReadError, produced.endReason)
	frames := produced.decoded.([]parsedMCTP)
	require.Len(t, frames, 3)
	require.Equal(t, parsedMCTP{Direction: "read", Payload: []byte("GET / HTTP/1.1\r\n")}, frames[2])
}

func TestHandleMCTPOversizeBodyTruncated(t *testing.T) {
	client, hp, done := startMCTP(t)
	body := "Segment-Num:1\r\nSegment-Seq:1\r\nData-Length:70000\r\n\r\n" + strings.Repeat("A", 70000)
	req := "REMOTE HI_SRDK_NET_SetWebServerPort MCTP/1.0\r\nCSeq:9\r\nContent-Length:" + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	go func() { _, _ = client.Write([]byte(req)) }()
	reply := readMCTPReply(t, client)
	require.Equal(t, mctp.BuildResponse("9", 0), reply)
	require.NoError(t, client.Close())

	produced, err := waitMCTP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedMCTP)
	require.Len(t, frames, 2)
	require.True(t, frames[0].Truncated)
	require.Equal(t, "HI_SRDK_NET_SetWebServerPort", frames[0].Command)
	require.Less(t, len(frames[0].Payload), mctpMaxBody+256)
}

func TestHandleMCTPBodyTooLarge(t *testing.T) {
	client, hp, done := startMCTP(t)
	_, err := client.Write([]byte("REMOTE HI_SRDK_DEV_SaveFlash MCTP/1.0\r\nCSeq:1\r\nContent-Length:99999999\r\n\r\n"))
	require.NoError(t, err)

	produced, err := waitMCTP(t, hp, done)
	require.ErrorIs(t, err, mctp.ErrBodyTooLarge)
	frames := produced.decoded.([]parsedMCTP)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
}
