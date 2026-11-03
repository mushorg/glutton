package cassandra

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// criminalipDescribe is the frame captured from criminalip on tcp/9160
// (run-1793746947 event #103): strict CALL describe_cluster_name, seqid 2.
var criminalipDescribe = []byte{
	0x00, 0x00, 0x00, 0x22, 0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15,
	'd', 'e', 's', 'c', 'r', 'i', 'b', 'e', '_', 'c', 'l', 'u', 's', 't', 'e', 'r', '_', 'n', 'a', 'm', 'e',
	0x00, 0x00, 0x00, 0x02, 0x00,
}

func TestReadFrameAndParse(t *testing.T) {
	raw, err := ReadFrame(bytes.NewReader(criminalipDescribe))
	require.NoError(t, err)
	require.Equal(t, criminalipDescribe, raw)
	msg, err := ParseMessage(raw[FrameHeaderLen:])
	require.NoError(t, err)
	require.Equal(t, Message{Name: "describe_cluster_name", Type: TypeCall, SeqID: 2, Strict: true, Args: map[string]any{}}, msg)
}

func TestReadFrameErrors(t *testing.T) {
	raw, err := ReadFrame(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")))
	var fe *FrameError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, []byte("GET "), raw)

	raw, err = ReadFrame(bytes.NewReader(criminalipDescribe[:10]))
	require.Error(t, err)
	require.Equal(t, criminalipDescribe[:10], raw)

	_, err = ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}))
	require.ErrorAs(t, err, &fe)
}

func TestParseMessageOldFormat(t *testing.T) {
	body := binary.BigEndian.AppendUint32(nil, 4)
	body = append(body, "ping"...)
	body = append(body, TypeCall, 0, 0, 0, 7, tStop)
	msg, err := ParseMessage(body)
	require.NoError(t, err)
	require.Equal(t, Message{Name: "ping", Type: TypeCall, SeqID: 7, Args: map[string]any{}}, msg)
}

func TestParseMessageBadVersion(t *testing.T) {
	_, err := ParseMessage([]byte{0x80, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	require.Error(t, err)
	_, err = ParseMessage([]byte{0x80, 0x01, 0x00, 0x01, 0, 0, 0, 0x40})
	require.Error(t, err)
}

func TestParseMessageArgs(t *testing.T) {
	// login(1: {1: map<string,string>{username: cassandra, password: cassandra}})
	fields := []byte{tStruct, 0, 1, tMap, 0, 1, tString, tString, 0, 0, 0, 2}
	for _, s := range []string{"username", "admin", "password", "hunter2"} {
		fields = appendString(fields, s)
	}
	fields = append(fields, tStop, tStop)
	frame := BuildMessage(TypeCall, "login", 1, fields)
	msg, err := ParseMessage(frame[FrameHeaderLen:])
	require.NoError(t, err)
	require.Equal(t, map[string]any{"1": map[string]any{"1": map[string]any{"username": "admin", "password": "hunter2"}}}, msg.Args)

	// A huge container size leaves Args nil but keeps the header.
	bad := BuildMessage(TypeCall, "x", 1, []byte{tList, 0, 1, tI32, 0x7f, 0xff, 0xff, 0xff})
	msg, err = ParseMessage(bad[FrameHeaderLen:])
	require.NoError(t, err)
	require.Equal(t, "x", msg.Name)
	require.Nil(t, msg.Args)
}

func TestBuildReplyAndException(t *testing.T) {
	reply := BuildReply("describe_cluster_name", 2, StringResult("Test Cluster"))
	want := append([]byte{0, 0, 0, 0x35, 0x80, 0x01, 0x00, 0x02, 0, 0, 0, 0x15}, "describe_cluster_name"...)
	want = append(want, 0, 0, 0, 2, tString, 0, 0, 0, 0, 0, 12)
	want = append(want, "Test Cluster"...)
	want = append(want, tStop)
	require.Equal(t, want, reply)

	exc := BuildException("foo", 9, "Invalid method name: 'foo'", ExceptionUnknownMethod)
	msg, err := ParseMessage(exc[FrameHeaderLen:])
	require.NoError(t, err)
	require.Equal(t, TypeException, msg.Type)
	require.Equal(t, int32(9), msg.SeqID)
	require.Equal(t, map[string]any{"1": "Invalid method name: 'foo'", "2": int32(1)}, msg.Args)
}
