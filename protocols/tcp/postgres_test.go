package tcp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/postgres"
	"github.com/stretchr/testify/require"
)

// postgresSSLRequest is the SSLRequest sent to tcp/5432 in Ochi event
// 940f5806-34a2-476f-979c-5f1d945cdc8f.
var postgresSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

var postgresTestSalt = [4]byte{0x01, 0x02, 0x03, 0x04}

// postgresStartup builds a synthetic StartupMessage for the given protocol
// version and name/value pairs, as psql sends it.
func postgresStartup(version uint32, params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, version)
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...)
}

// postgresMessage frames body as a typed frontend message.
func postgresMessage(t byte, body string) []byte {
	b := append([]byte{t}, binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))...)
	return append(b, body...)
}

func startPostgres(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	prevSalt := postgresSalt
	postgresSalt = func() [4]byte { return postgresTestSalt }
	t.Cleanup(func() { postgresSalt = prevSalt })
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandlePostgres(context.Background(), serverConn, connection.Metadata{TargetPort: 5432}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// finishPostgres closes the client, waits for the handler and returns the
// single produced event.
func finishPostgres(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedPostgres) {
	t.Helper()
	require.NoError(t, client.Close())
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, "postgres", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedPostgres)
	require.True(t, ok)
	return produced, events
}

func writePostgres(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	_, err := conn.Write(b)
	require.NoError(t, err)
}

func readPostgres(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b
}

var postgresSSLRead = parsedPostgres{Direction: "read", Command: "SSLRequest", Payload: postgresSSLRequest}
var postgresSSLWrite = parsedPostgres{Direction: "write", Command: "SSLResponse", Status: "N", Payload: []byte{'N'}}

func TestHandlePostgresSSLRequestDeclined(t *testing.T) {
	client, hp, done := startPostgres(t)

	writePostgres(t, client, postgresSSLRequest)
	require.Equal(t, []byte{'N'}, readPostgres(t, client, 1))

	produced, events := finishPostgres(t, client, hp, done)
	require.Equal(t, postgresSSLRequest, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedPostgres{postgresSSLRead, postgresSSLWrite}, events)
}

func TestHandlePostgresPasswordFailedRecordsPassword(t *testing.T) {
	client, hp, done := startPostgres(t)

	writePostgres(t, client, postgresSSLRequest)
	readPostgres(t, client, 1)
	startup := postgresStartup(postgres.ProtocolVersion3,
		"user", "postgres", "database", "postgres", "application_name", "psql", "client_encoding", "UTF8")
	writePostgres(t, client, startup)
	authMD5 := postgres.BuildAuthMD5(postgresTestSalt)
	require.Equal(t, authMD5, readPostgres(t, client, len(authMD5)))
	password := postgresMessage('p', "md5c0ffeec0ffeec0ffeec0ffeec0ffee12\x00")
	writePostgres(t, client, password)
	failed := postgres.PasswordFailed("postgres")
	require.Equal(t, failed.Build(), readPostgres(t, client, len(failed.Build())))
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	events := produced.decoded.([]parsedPostgres)
	require.Equal(t, []parsedPostgres{
		postgresSSLRead,
		postgresSSLWrite,
		{
			Direction: "read", Command: "StartupMessage", Path: "postgres", Payload: startup,
			ProtocolVersion: "3.0", User: "postgres", ApplicationName: "psql",
			Params: map[string]string{"client_encoding": "UTF8"},
		},
		{Direction: "write", Command: "AuthenticationMD5Password", Payload: authMD5},
		{Direction: "read", Command: "PasswordMessage", Payload: password, Password: "md5c0ffeec0ffeec0ffeec0ffeec0ffee12"},
		{
			Direction: "write", Command: "ErrorResponse", Status: "28P01",
			Message: `password authentication failed for user "postgres"`, Payload: failed.Build(),
		},
	}, events)

	// the md5 hash string the client sent is in the decoded frame
	encoded, err := json.Marshal(events[4])
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"password":"md5c0ffeec0ffeec0ffeec0ffeec0ffee12"`)
}

func TestHandlePostgresNegotiatesMinorVersion(t *testing.T) {
	client, hp, done := startPostgres(t)

	startup := postgresStartup(postgres.ProtocolVersion3|2, "user", "admin", "_pq_.test", "1")
	writePostgres(t, client, startup)
	negotiate := postgres.BuildNegotiateProtocolVersion([]string{"_pq_.test"})
	require.Equal(t, negotiate, readPostgres(t, client, len(negotiate)))
	authMD5 := postgres.BuildAuthMD5(postgresTestSalt)
	require.Equal(t, authMD5, readPostgres(t, client, len(authMD5)))
	terminate := postgresMessage('X', "")
	writePostgres(t, client, terminate)
	waitHandlerDone(t, done)

	events := waitProduced(t, hp).decoded.([]parsedPostgres)
	require.Equal(t, []parsedPostgres{
		{
			Direction: "read", Command: "StartupMessage", Payload: startup, ProtocolVersion: "3.2",
			User: "admin", Params: map[string]string{"_pq_.test": "1"},
		},
		{Direction: "write", Command: "NegotiateProtocolVersion", Payload: negotiate},
		{Direction: "write", Command: "AuthenticationMD5Password", Payload: authMD5},
		{Direction: "read", Command: "Terminate", Payload: terminate},
	}, events)
}

func TestHandlePostgresStartupErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		startup []byte
		reply   postgres.Error
	}{
		"protocol 2":       {postgresStartup(2<<16, "user", "postgres"), postgres.UnsupportedProtocol(2, 0)},
		"no user":          {postgresStartup(postgres.ProtocolVersion3, "database", "postgres"), postgres.NoUser()},
		"repeated SSL":     {postgresSSLRequest, postgres.UnsupportedProtocol(1234, 5679)},
		"query before pwd": {nil, postgres.ExpectedPassword('Q')},
	} {
		t.Run(name, func(t *testing.T) {
			client, hp, done := startPostgres(t)
			var first []byte
			switch name {
			case "repeated SSL":
				writePostgres(t, client, postgresSSLRequest)
				readPostgres(t, client, 1)
				first = postgresSSLRequest
			case "query before pwd":
				first = postgresStartup(postgres.ProtocolVersion3, "user", "postgres")
				writePostgres(t, client, first)
				readPostgres(t, client, len(postgres.BuildAuthMD5(postgresTestSalt)))
				tc.startup = postgresMessage('Q', "SELECT 1\x00")
			}
			writePostgres(t, client, tc.startup)
			want := tc.reply.Build()
			require.Equal(t, want, readPostgres(t, client, len(want)))
			waitHandlerDone(t, done)

			produced := waitProduced(t, hp)
			require.Empty(t, hp.produced, "exactly one event per session")
			if first == nil {
				first = tc.startup
			}
			require.Equal(t, first, produced.payload)
			events := produced.decoded.([]parsedPostgres)
			require.Equal(t, parsedPostgres{
				Direction: "write", Command: "ErrorResponse", Status: tc.reply.Code, Message: tc.reply.Message, Payload: want,
			}, events[len(events)-1])
		})
	}
}

func TestHandlePostgresMalformedStartupClosesSilently(t *testing.T) {
	client, hp, done := startPostgres(t)

	// the parameter list lacks its terminating empty name
	startup := postgresStartup(postgres.ProtocolVersion3, "user", "postgres")
	startup = startup[:len(startup)-1]
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))
	writePostgres(t, client, startup)
	waitHandlerDone(t, done)

	require.Equal(t, []parsedPostgres{
		{Direction: "read", Command: "StartupMessage", Payload: startup, ProtocolVersion: "3.0", User: "postgres"},
	}, waitProduced(t, hp).decoded.([]parsedPostgres))
}

func TestHandlePostgresEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startPostgres(t)

	startup := postgresStartup(postgres.ProtocolVersion3, "user", "postgres")
	writePostgres(t, client, startup[:12])
	produced, events := finishPostgres(t, client, hp, done)
	require.Equal(t, startup[:12], produced.payload)
	require.Equal(t, []parsedPostgres{
		{Direction: "read", Command: "StartupMessage", Payload: startup[:12], Truncated: true},
	}, events)
}

func TestHandlePostgresOversizeIsCapped(t *testing.T) {
	client, hp, done := startPostgres(t)

	huge := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}
	writePostgres(t, client, huge)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedPostgres{
		{Direction: "read", Payload: huge[:4], Truncated: true},
	}, produced.decoded.([]parsedPostgres))
}

func TestHandlePostgresCancelRequestCloses(t *testing.T) {
	client, hp, done := startPostgres(t)

	cancel := []byte{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 1, 0, 0, 0, 2}
	writePostgres(t, client, cancel)
	waitHandlerDone(t, done)
	require.Equal(t, []parsedPostgres{
		{Direction: "read", Command: "CancelRequest", Payload: cancel},
	}, waitProduced(t, hp).decoded.([]parsedPostgres))
}
