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
	"github.com/mushorg/glutton/protocols/tcp/mongodb"
	"github.com/stretchr/testify/require"
)

func TestBuildResponseOpMsgOk(t *testing.T) {
	requestHeader := mongodb.Header{
		MessageLength: 100,
		RequestID:     12345,
		ResponseTo:    0,
		OpCode:        mongodb.OpMsg,
	}

	responseHeader, response, err := mongodb.BuildResponse(requestHeader, "ping")
	require.NoError(t, err)
	require.NotNil(t, response)

	require.Equal(t, int32(len(response)), responseHeader.MessageLength)
	require.Equal(t, requestHeader.RequestID+1, responseHeader.RequestID)
	require.Equal(t, requestHeader.RequestID, responseHeader.ResponseTo)
	require.Equal(t, mongodb.OpMsg, responseHeader.OpCode)

	require.Equal(t, int32(len(response)), int32(binary.LittleEndian.Uint32(response[0:4])))
	require.Equal(t, uint32(0), binary.LittleEndian.Uint32(response[16:20]))
	require.Equal(t, byte(0), response[20])

	document := response[21:]
	require.GreaterOrEqual(t, len(document), 17)
	require.Equal(t, byte(0x01), document[4])
	require.Equal(t, []byte("ok"), document[5:7])
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F}, document[8:16])
}

func readMongoMessage(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 16)
	_, err := io.ReadFull(conn, hdr)
	require.NoError(t, err)
	n := binary.LittleEndian.Uint32(hdr[0:4])
	require.Greater(t, n, uint32(16))
	msg := make([]byte, n)
	copy(msg, hdr)
	_, err = io.ReadFull(conn, msg[16:])
	require.NoError(t, err)
	return msg
}

func mongoOpcode(msg []byte) int32 {
	return int32(binary.LittleEndian.Uint32(msg[12:16]))
}

func TestHandleMongoDBHelloIsMasterBuildInfo(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMongoDB(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))

	requests := [][]byte{
		mongodb.WrapOpQuery(1, "admin.$cmd", mongodb.CmdDoc("hello")),
		mongodb.WrapOpQuery(2, "admin.$cmd", mongodb.CmdDoc("isMaster")),
		mongodb.WrapOpMsg(3, mongodb.CmdDoc("hello", mongodb.StringField("$db", "admin"))),
		mongodb.WrapOpQuery(100, "admin.$cmd", mongodb.CmdDoc("buildInfo")),
		mongodb.WrapOpMsg(101, mongodb.CmdDoc("buildInfo", mongodb.StringField("$db", "admin"))),
	}

	var replies [][]byte
	for _, req := range requests {
		_, err := client.Write(req)
		require.NoError(t, err)
		replies = append(replies, readMongoMessage(t, client))
	}

	require.Equal(t, mongodb.OpReply, mongoOpcode(replies[0]))
	require.Contains(t, string(replies[0]), "ismaster")
	require.Contains(t, string(replies[0]), "maxWireVersion")

	require.Equal(t, mongodb.OpReply, mongoOpcode(replies[1]))
	require.Contains(t, string(replies[1]), "isWritablePrimary")

	require.Equal(t, mongodb.OpMsg, mongoOpcode(replies[2]))
	require.Contains(t, string(replies[2]), "ismaster")

	require.Equal(t, mongodb.OpReply, mongoOpcode(replies[3]))
	require.Contains(t, string(replies[3]), "versionArray")
	require.Contains(t, string(replies[3]), "7.0.0")

	require.Equal(t, mongodb.OpMsg, mongoOpcode(replies[4]))
	require.Contains(t, string(replies[4]), "version")

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "mongodb", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedMongoDB)
	require.True(t, ok)
	require.Len(t, events, 10)

	wantCmds := []string{"hello", "isMaster", "hello", "buildInfo", "buildInfo"}
	wantReadOps := []int32{mongodb.OpQuery, mongodb.OpQuery, mongodb.OpMsg, mongodb.OpQuery, mongodb.OpMsg}
	wantWriteOps := []int32{mongodb.OpReply, mongodb.OpReply, mongodb.OpMsg, mongodb.OpReply, mongodb.OpMsg}
	for i := 0; i < 5; i++ {
		read := events[i*2]
		write := events[i*2+1]
		require.Equal(t, "read", read.Direction)
		require.Equal(t, wantCmds[i], read.Command)
		require.Equal(t, wantReadOps[i], read.Header.OpCode)
		require.Equal(t, requests[i], read.Payload)
		require.Equal(t, "write", write.Direction)
		require.Equal(t, wantCmds[i], write.Command)
		require.Equal(t, "ok", write.Status)
		require.Equal(t, wantWriteOps[i], write.Header.OpCode)
		require.Equal(t, requests[i][4:8], write.Payload[8:12]) // ResponseTo == request RequestID
	}
}

func TestHandleMongoDBEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMongoDB(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "mongodb", produced.protocol)
	events, ok := produced.decoded.([]parsedMongoDB)
	require.True(t, ok)
	require.Empty(t, events)
}

func TestHandleMongoDBOpQueryUnknownCommandUsesOpReply(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMongoDB(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	req := mongodb.WrapOpQuery(7, "admin.$cmd", mongodb.CmdDoc("ping"))
	_, err := client.Write(req)
	require.NoError(t, err)

	resp := readMongoMessage(t, client)
	require.Equal(t, mongodb.OpReply, mongoOpcode(resp))
	require.True(t, bytes.Contains(resp, []byte("ok")))
	require.False(t, bytes.Contains(resp, []byte("ismaster")))

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedMongoDB)
	require.True(t, ok)
	require.Equal(t, "ping", events[0].Command)
	require.Equal(t, mongodb.OpReply, events[1].Header.OpCode)
}
