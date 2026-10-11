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
	"github.com/mushorg/glutton/protocols/tcp/firebird"
	"github.com/stretchr/testify/require"
)

// nmap Firebird probe (user "scanner", host "nmap", service_mgr, protocols 8
// and 10) sent by Shodan to tcp/3050 in Ochi event
// e0fc5f6b-f5e3-4d4f-b68d-e2366279125c.
var firebirdNmapConnect = []byte("\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00$\x00\x00\x00\x0bservice_mgr\x00\x00\x00\x00\x02\x00\x00\x00\x13\x01\x08scanner \x04\x05nmap \x06\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\n\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04")

var firebirdNmapRead = parsedFirebird{
	Direction:  "read",
	Command:    "connect",
	Path:       "service_mgr",
	Payload:    firebirdNmapConnect,
	Operation:  "attach",
	ClientArch: 36,
	OSUser:     "scanner ",
	ClientHost: "nmap ",
	Protocols: []firebirdProtocol{
		{Version: 8, Arch: 1, MinType: 2, MaxType: 3, Weight: 2},
		{Version: 10, Arch: 1, MinType: 2, MaxType: 3, Weight: 4},
	},
}

var firebirdAccept10 = []byte{0, 0, 0, 3, 0, 0, 0, 0x0a, 0, 0, 0, 1, 0, 0, 0, 3}

// firebirdServiceAttach is a synthetic op_service_attach with an SPB
// version 2 user name and password, as fdb/Jaybird send it.
func firebirdServiceAttach(user, password string) []byte {
	spb := []byte{2, 2, 28, byte(len(user))}
	spb = append(spb, user...)
	spb = append(spb, 29, byte(len(password)))
	spb = append(spb, password...)
	b := binary.BigEndian.AppendUint32(nil, firebird.OpServiceAttach)
	b = binary.BigEndian.AppendUint32(b, 0)
	for _, s := range [][]byte{[]byte("service_mgr"), spb} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
		b = append(b, make([]byte, (4-len(s)%4)%4)...)
	}
	return b
}

func startFirebird(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleFirebird(context.Background(), serverConn, connection.Metadata{TargetPort: 3050}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// finishFirebird closes the client, waits for the handler and returns the
// single produced event.
func finishFirebird(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedFirebird) {
	t.Helper()
	require.NoError(t, client.Close())
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, "firebird", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedFirebird)
	require.True(t, ok)
	return produced, events
}

func writeFirebird(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	_, err := conn.Write(b)
	require.NoError(t, err)
}

func readFirebird(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b
}

func TestHandleFirebirdNmapProbe(t *testing.T) {
	client, hp, done := startFirebird(t)

	writeFirebird(t, client, firebirdNmapConnect)
	require.Equal(t, firebirdAccept10, readFirebird(t, client, len(firebirdAccept10)))

	produced, events := finishFirebird(t, client, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedFirebird{
		firebirdNmapRead,
		{Direction: "write", Status: "accept", Payload: firebirdAccept10, ProtocolVersion: 10},
	}, events)
}

func TestHandleFirebirdServiceAttachLoginFailedRecordsPassword(t *testing.T) {
	client, hp, done := startFirebird(t)

	writeFirebird(t, client, firebirdNmapConnect)
	readFirebird(t, client, len(firebirdAccept10))
	attach := firebirdServiceAttach("SYSDBA", "masterkey")
	writeFirebird(t, client, attach)
	loginFailed := firebird.BuildLoginFailed()
	require.Equal(t, loginFailed, readFirebird(t, client, len(loginFailed)))
	// a second guess on the same connection is answered too
	writeFirebird(t, client, attach)
	readFirebird(t, client, len(loginFailed))

	_, events := finishFirebird(t, client, hp, done)
	attachRead := parsedFirebird{
		Direction: "read", Command: "service_attach", Path: "service_mgr", Payload: attach,
		Username: "SYSDBA", Password: "masterkey",
	}
	failed := parsedFirebird{Direction: "write", Status: "login_failed", Payload: loginFailed, ErrorCode: firebird.ISCLogin}
	require.Equal(t, []parsedFirebird{
		firebirdNmapRead,
		{Direction: "write", Status: "accept", Payload: firebirdAccept10, ProtocolVersion: 10},
		attachRead, failed, attachRead, failed,
	}, events)

	// the guessed password is in the decoded frame, not only the raw payload
	encoded, err := json.Marshal(attachRead)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"password":"masterkey"`)
}

func TestHandleFirebirdRejectsUnsupportedProtocols(t *testing.T) {
	client, hp, done := startFirebird(t)

	// the nmap probe with both entries swapped for Firebird 3 protocol 13
	probe := append([]byte(nil), firebirdNmapConnect...)
	binary.BigEndian.PutUint32(probe[60:], 0x800d)
	binary.BigEndian.PutUint32(probe[80:], 0x800d)
	writeFirebird(t, client, probe)
	require.Equal(t, firebird.BuildReject(), readFirebird(t, client, 4))
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedFirebird)
	require.Len(t, events, 2)
	require.Equal(t, uint32(13), events[0].Protocols[0].Version)
	require.Equal(t, parsedFirebird{Direction: "write", Status: "reject", Payload: firebird.BuildReject()}, events[1])
}

func TestHandleFirebirdEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startFirebird(t)

	writeFirebird(t, client, firebirdNmapConnect[:40])
	_, events := finishFirebird(t, client, hp, done)
	require.Equal(t, []parsedFirebird{
		{Direction: "read", Command: "connect", Payload: firebirdNmapConnect[:40], Truncated: true},
	}, events)
}

func TestHandleFirebirdOversizeIsCapped(t *testing.T) {
	client, hp, done := startFirebird(t)

	// op_connect whose file name length passes the packet cap
	huge := []byte{0, 0, 0, 1, 0, 0, 0, 0x13, 0, 0, 0, 2, 0, 0, 0, 0x24, 0, 0x10, 0, 0}
	writeFirebird(t, client, huge)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedFirebird{
		{Direction: "read", Command: "connect", Payload: huge, Truncated: true},
	}, produced.decoded.([]parsedFirebird))
}

func TestHandleFirebirdAttachBeforeConnectEndsSession(t *testing.T) {
	client, hp, done := startFirebird(t)

	attach := firebirdServiceAttach("SYSDBA", "masterkey")
	writeFirebird(t, client, attach)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, []parsedFirebird{
		{Direction: "read", Command: "service_attach", Payload: attach},
	}, produced.decoded.([]parsedFirebird))
}

func TestHandleFirebirdUnknownOpEndsSession(t *testing.T) {
	client, hp, done := startFirebird(t)

	writeFirebird(t, client, firebirdNmapConnect)
	readFirebird(t, client, len(firebirdAccept10))
	unknown := []byte{0, 0, 0, 0x63, 0xde, 0xad, 0xbe, 0xef}
	writeFirebird(t, client, unknown)
	waitHandlerDone(t, done)
	events := waitProduced(t, hp).decoded.([]parsedFirebird)
	require.Len(t, events, 3)
	require.Equal(t, "op_99", events[2].Command)
	require.False(t, events[2].Truncated)
	require.NotEmpty(t, events[2].Payload)
}
