package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/cassandra"
	"github.com/stretchr/testify/require"
)

// cassandraCriminalipDescribe is the 38-byte frame captured from criminalip
// on tcp/9160 (run-1793746947 event #103): framed strict-binary Thrift CALL
// describe_cluster_name, seqid 2, empty args.
var cassandraCriminalipDescribe = []byte{
	0x00, 0x00, 0x00, 0x22, 0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x5f, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00,
	0x02, 0x00,
}

func startCassandra(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleCassandra(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return client, hp, done
}

func waitCassandra(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	produced := waitProduced(t, hp)
	require.NoError(t, <-done)
	require.Equal(t, "cassandra", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("unexpected second event: %+v", extra)
	default:
	}
	return produced
}

func readCassandraFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	raw, err := cassandra.ReadFrame(conn)
	require.NoError(t, err)
	return raw
}

func TestHandleCassandraDescribeClusterName(t *testing.T) {
	client, hp, done := startCassandra(t)

	_, err := client.Write(cassandraCriminalipDescribe)
	require.NoError(t, err)
	reply := readCassandraFrame(t, client)
	wantReply := cassandra.BuildReply("describe_cluster_name", 2, cassandra.StringResult("Test Cluster"))
	require.Equal(t, wantReply, reply)

	// The session continues: an unknown method gets an exception.
	call := cassandra.BuildMessage(cassandra.TypeCall, "describe_ring", 3, []byte{0x00})
	_, err = client.Write(call)
	require.NoError(t, err)
	exc := readCassandraFrame(t, client)
	wantExc := cassandra.BuildException("describe_ring", 3, "Invalid method name: 'describe_ring'", cassandra.ExceptionUnknownMethod)
	require.Equal(t, wantExc, exc)
	require.NoError(t, client.Close())

	produced := waitCassandra(t, hp, done)
	require.Equal(t, cassandraCriminalipDescribe, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCassandra{
		{
			Direction: "read",
			Command:   "describe_cluster_name",
			Message:   &cassandra.Message{Name: "describe_cluster_name", Type: cassandra.TypeCall, SeqID: 2, Strict: true, Args: map[string]any{}},
			Payload:   cassandraCriminalipDescribe,
		},
		{Direction: "write", Command: "describe_cluster_name", Status: "reply", Payload: wantReply},
		{
			Direction: "read",
			Command:   "describe_ring",
			Message:   &cassandra.Message{Name: "describe_ring", Type: cassandra.TypeCall, SeqID: 3, Strict: true, Args: map[string]any{}},
			Payload:   call,
		},
		{Direction: "write", Command: "describe_ring", Status: "exception", Payload: wantExc},
	}, produced.decoded)
}

func TestHandleCassandraLoginAndQuery(t *testing.T) {
	client, hp, done := startCassandra(t)

	creds := []byte{12, 0, 1, 13, 0, 1, 11, 11, 0, 0, 0, 2}
	for _, s := range []string{"username", "cassandra", "password", "cassandra"} {
		creds = append(creds, 0, 0, 0, byte(len(s)))
		creds = append(creds, s...)
	}
	creds = append(creds, 0, 0)
	_, err := client.Write(cassandra.BuildMessage(cassandra.TypeCall, "login", 1, creds))
	require.NoError(t, err)
	require.Equal(t, cassandra.BuildReply("login", 1, cassandra.VoidResult()), readCassandraFrame(t, client))

	q := "SELECT * FROM system.local"
	query := append([]byte{11, 0, 1, 0, 0, 0, byte(len(q))}, q...)
	query = append(query, 0)
	_, err = client.Write(cassandra.BuildMessage(cassandra.TypeCall, "execute_cql3_query", 2, query))
	require.NoError(t, err)
	readCassandraFrame(t, client)
	require.NoError(t, client.Close())

	frames := waitCassandra(t, hp, done).decoded.([]parsedCassandra)
	require.Len(t, frames, 4)
	require.Equal(t, "cassandra", frames[0].Username)
	require.Equal(t, "cassandra", frames[0].Password)
	require.Equal(t, q, frames[2].Query)
	require.Equal(t, "exception", frames[3].Status)
}

func TestHandleCassandraBadFrameLength(t *testing.T) {
	client, hp, done := startCassandra(t)

	junk := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() { _, _ = client.Write(junk) }() // handler stops after the length prefix

	produced := waitCassandra(t, hp, done)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedCassandra{{Direction: "read", Payload: junk[:4]}}, produced.decoded)
}

func TestHandleCassandraMalformedMessage(t *testing.T) {
	client, hp, done := startCassandra(t)

	bad := []byte{0, 0, 0, 8, 0x80, 0x02, 0x00, 0x01, 0, 0, 0, 0}
	_, err := client.Write(bad)
	require.NoError(t, err)

	produced := waitCassandra(t, hp, done)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedCassandra{{Direction: "read", Payload: bad}}, produced.decoded)
}

func TestHandleCassandraEarlyDisconnect(t *testing.T) {
	client, hp, done := startCassandra(t)

	_, err := client.Write(cassandraCriminalipDescribe[:20])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced := waitCassandra(t, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCassandra{{Direction: "read", Payload: cassandraCriminalipDescribe[:20]}}, produced.decoded)
}

func TestHandleCassandraNoData(t *testing.T) {
	client, hp, done := startCassandra(t)
	require.NoError(t, client.Close())

	produced := waitCassandra(t, hp, done)
	require.Empty(t, produced.decoded)
}
