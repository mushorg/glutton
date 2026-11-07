package tcp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/cql"
	"github.com/stretchr/testify/require"
)

// cqlBinaryedgeOptions is the 9-byte frame captured from binaryedge on
// tcp/9042 (run-1794063438-2 event #6): CQL v4 OPTIONS, stream 1, no body.
var cqlBinaryedgeOptions = []byte{0x04, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00}

// cqlSupportedV4Stream1 is the SUPPORTED reply a stock Cassandra 3.11 node
// sends to cqlBinaryedgeOptions.
var cqlSupportedV4Stream1 = []byte{
	0x84, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00, 0x00, 0x34,
	0x00, 0x02,
	0x00, 0x0b, 'C', 'O', 'M', 'P', 'R', 'E', 'S', 'S', 'I', 'O', 'N',
	0x00, 0x02, 0x00, 0x06, 's', 'n', 'a', 'p', 'p', 'y', 0x00, 0x03, 'l', 'z', '4',
	0x00, 0x0b, 'C', 'Q', 'L', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N',
	0x00, 0x01, 0x00, 0x05, '3', '.', '4', '.', '4',
}

func startCQL(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleCQL(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return client, hp, done
}

func waitCQL(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	produced := waitProduced(t, hp)
	require.NoError(t, <-done)
	require.Equal(t, "cql", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("unexpected second event: %+v", extra)
	default:
	}
	return produced
}

func cqlRequest(stream int16, opcode uint8, body []byte) []byte {
	out := []byte{0x04, 0x00, 0x00, 0x00, opcode}
	binary.BigEndian.PutUint16(out[2:4], uint16(stream))
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}

func cqlStringMap(kv ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(kv)/2))
	for _, s := range kv {
		b = append(b, cql.StringBody(s)...)
	}
	return b
}

func cqlExchange(t *testing.T, client net.Conn, req []byte) []byte {
	t.Helper()
	_, err := client.Write(req)
	require.NoError(t, err)
	reply, _, err := cql.ReadFrame(client)
	require.NoError(t, err)
	return reply
}

func cqlHeader(stream int16, opcode uint8, length int) *cql.Header {
	return &cql.Header{Version: 4, Stream: stream, Opcode: opcode, Length: uint32(length)}
}

func TestHandleCQLBinaryedgeOptions(t *testing.T) {
	client, hp, done := startCQL(t)

	reply := cqlExchange(t, client, cqlBinaryedgeOptions)
	require.Equal(t, cqlSupportedV4Stream1, reply)
	require.NoError(t, client.Close())

	produced := waitCQL(t, hp, done)
	require.Equal(t, cqlBinaryedgeOptions, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Header: cqlHeader(1, cql.OpOptions, 0), Command: "OPTIONS", Payload: cqlBinaryedgeOptions},
		{Direction: "write", Command: "SUPPORTED", Status: "supported", Payload: cqlSupportedV4Stream1},
	}, produced.decoded)
}

func TestHandleCQLLoginAndQuery(t *testing.T) {
	client, hp, done := startCQL(t)

	startupBody := cqlStringMap("CQL_VERSION", "3.0.0", "DRIVER_NAME", "probe")
	startup := cqlRequest(2, cql.OpStartup, startupBody)
	authenticate := cqlExchange(t, client, startup)
	wantAuthenticate := cql.BuildFrame(4, 2, cql.OpAuthenticate, cql.StringBody("org.apache.cassandra.auth.PasswordAuthenticator"))
	require.Equal(t, wantAuthenticate, authenticate)

	token := []byte("\x00cassandra\x00s3cret")
	authBody := binary.BigEndian.AppendUint32(nil, uint32(len(token)))
	authBody = append(authBody, token...)
	authResp := cqlRequest(3, cql.OpAuthResponse, authBody)
	success := cqlExchange(t, client, authResp)
	wantSuccess := cql.BuildFrame(4, 3, cql.OpAuthSuccess, cql.NullBytes())
	require.Equal(t, wantSuccess, success)

	register := cqlRequest(4, cql.OpRegister, append([]byte{0x00, 0x01}, cql.StringBody("STATUS_CHANGE")...))
	ready := cqlExchange(t, client, register)
	wantReady := cql.BuildFrame(4, 4, cql.OpReady, nil)
	require.Equal(t, wantReady, ready)

	q := "SELECT * FROM system.local"
	queryBody := binary.BigEndian.AppendUint32(nil, uint32(len(q)))
	queryBody = append(queryBody, q...)
	queryBody = append(queryBody, 0x00, 0x01, 0x00) // consistency ONE, no flags
	query := cqlRequest(5, cql.OpQuery, queryBody)
	qErr := cqlExchange(t, client, query)
	wantQErr := cql.BuildFrame(4, 5, cql.OpError, cql.ErrorBody(cql.ErrIsBootstrapping, "Cannot read from a bootstrapping node"))
	require.Equal(t, wantQErr, qErr)

	require.NoError(t, client.Close())
	produced := waitCQL(t, hp, done)
	require.Equal(t, startup, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Header: cqlHeader(2, cql.OpStartup, len(startupBody)), Command: "STARTUP",
			Options: map[string]string{"CQL_VERSION": "3.0.0", "DRIVER_NAME": "probe"}, Payload: startup},
		{Direction: "write", Command: "AUTHENTICATE", Status: "authenticate", Payload: wantAuthenticate},
		{Direction: "read", Header: cqlHeader(3, cql.OpAuthResponse, len(authBody)), Command: "AUTH_RESPONSE",
			Username: "cassandra", Password: "s3cret", Payload: authResp},
		{Direction: "write", Command: "AUTH_SUCCESS", Status: "auth_success", Payload: wantSuccess},
		{Direction: "read", Header: cqlHeader(4, cql.OpRegister, len(register)-cql.HeaderLen), Command: "REGISTER", Payload: register},
		{Direction: "write", Command: "READY", Status: "ready", Payload: wantReady},
		{Direction: "read", Header: cqlHeader(5, cql.OpQuery, len(queryBody)), Command: "QUERY", Query: q, Payload: query},
		{Direction: "write", Command: "ERROR", Status: "is_bootstrapping", Payload: wantQErr},
	}, produced.decoded)
}

func TestHandleCQLQueryBeforeStartup(t *testing.T) {
	client, hp, done := startCQL(t)

	query := cqlRequest(7, cql.OpQuery, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	reply := cqlExchange(t, client, query)
	want := cql.BuildFrame(4, 7, cql.OpError, cql.ErrorBody(cql.ErrProtocol, "Unexpected message QUERY, expecting STARTUP or OPTIONS"))
	require.Equal(t, want, reply)

	// The connection stays usable.
	require.Equal(t, cqlSupportedV4Stream1, cqlExchange(t, client, cqlBinaryedgeOptions))
	require.NoError(t, client.Close())

	produced := waitCQL(t, hp, done)
	decoded := produced.decoded.([]parsedCQL)
	require.Len(t, decoded, 4)
	require.Equal(t, parsedCQL{Direction: "write", Command: "ERROR", Status: "protocol_error", Payload: want}, decoded[1])
}

func TestHandleCQLStartupWithoutVersion(t *testing.T) {
	client, hp, done := startCQL(t)

	reply := cqlExchange(t, client, cqlRequest(1, cql.OpStartup, cqlStringMap()))
	want := cql.BuildFrame(4, 1, cql.OpError, cql.ErrorBody(cql.ErrProtocol, "Missing value CQL_VERSION in STARTUP message"))
	require.Equal(t, want, reply)
	require.NoError(t, client.Close())
	waitCQL(t, hp, done)
}

func TestHandleCQLLegacyVersion(t *testing.T) {
	client, hp, done := startCQL(t)

	v2Options := []byte{0x02, 0x00, 0x09, 0x05, 0x00, 0x00, 0x00, 0x00}
	reply := cqlExchange(t, client, v2Options)
	want := cql.BuildFrame(2, 9, cql.OpError, cql.ErrorBody(cql.ErrProtocol,
		"Invalid or unsupported protocol version (2); supported versions are (3/v3, 4/v4, 5/v5-beta)"))
	require.Equal(t, want, reply)

	produced := waitCQL(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Header: &cql.Header{Version: 2, Stream: 9, Opcode: cql.OpOptions}, Command: "OPTIONS", Payload: v2Options},
		{Direction: "write", Command: "ERROR", Status: "protocol_error", Payload: want},
	}, produced.decoded)
}

func TestHandleCQLV5WithoutBeta(t *testing.T) {
	client, hp, done := startCQL(t)

	reply := cqlExchange(t, client, []byte{0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00})
	want := cql.BuildFrame(4, 0, cql.OpError, cql.ErrorBody(cql.ErrProtocol,
		"Beta version of the protocol used (5/v5-beta), but USE_BETA flag is unset"))
	require.Equal(t, want, reply)
	produced := waitCQL(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
}

func TestHandleCQLNonCQL(t *testing.T) {
	old := cqlDrainTimeout
	cqlDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { cqlDrainTimeout = old })

	client, hp, done := startCQL(t)
	probe := []byte("GET / HTTP/1.0\r\n\r\n")
	_, err := client.Write(probe)
	require.NoError(t, err)
	reply, _, err := cql.ReadFrame(client)
	require.NoError(t, err)
	want := cql.BuildFrame(4, 0, cql.OpError, cql.ErrorBody(cql.ErrProtocol,
		"Invalid or unsupported protocol version (71); supported versions are (3/v3, 4/v4, 5/v5-beta)"))
	require.Equal(t, want, reply)

	produced := waitCQL(t, hp, done)
	require.Equal(t, probe, produced.payload)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Payload: probe},
		{Direction: "write", Command: "ERROR", Status: "protocol_error", Payload: want},
	}, produced.decoded)
}

func TestHandleCQLOversizeBody(t *testing.T) {
	client, hp, done := startCQL(t)

	big := []byte{0x04, 0x00, 0x00, 0x01, cql.OpQuery, 0x00, 0x10, 0x00, 0x01}
	_, err := client.Write(big)
	require.NoError(t, err)

	produced := waitCQL(t, hp, done)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Header: cqlHeader(1, cql.OpQuery, 0x100001), Command: "QUERY", Payload: big, Truncated: true},
	}, produced.decoded)
}

func TestHandleCQLTruncatedHeader(t *testing.T) {
	client, hp, done := startCQL(t)

	_, err := client.Write(cqlBinaryedgeOptions[:5])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced := waitCQL(t, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCQL{
		{Direction: "read", Payload: cqlBinaryedgeOptions[:5]},
	}, produced.decoded)
}

func TestHandleCQLEarlyDisconnect(t *testing.T) {
	client, hp, done := startCQL(t)
	require.NoError(t, client.Close())

	produced := waitCQL(t, hp, done)
	require.Empty(t, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedCQL{}, produced.decoded)
}
