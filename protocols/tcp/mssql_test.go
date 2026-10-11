package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/mushorg/glutton/protocols/tcp/mssql"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
	"github.com/stretchr/testify/require"
)

// Nmap ms-sql-ntlm-info from Ochi event 024dea0c-f1a6-418f-b1a0-c2f50b093e1e:
// PRELOGIN, then a TDS 7.1 integrated-auth LOGIN7 with an NTLMSSP NEGOTIATE.
// The LOGIN7 ServerName is swapped for 198.51.100.10 (same length).
var (
	nmapMSSQLPrelogin = mustDecodeHex("1201003400000000000015000601001b000102001c000c0300280004ff08000155000002" +
		"4d5353514c5365727665720000003132")
	nmapMSSQLLogin7 = mustDecodeHex("100100c300000100bb00000001000071000000000700000" + "0aa56010000000000" +
		"a0830000000000000000000056000400" +
		"5e0000005e0000005e0008006e000d00" +
		"0000000088000900" + "9a0000009a000000" +
		"0000000000009a002100bb0000004e00" +
		"6d00610070004e006d00610070002000" +
		"4e00530045003100390038002e003500" +
		"31002e003100300030002e0031003000" +
		"6d007300730071006c002e006c007500" +
		"61004e544c4d5353500001000000" + "01b2" +
		"000001000100200000000000000020000000" + "2e")
)

func fixMSSQLChallenge(t *testing.T) {
	t.Helper()
	prevNow, prevChallenge := mssqlNow, mssqlServerChallenge
	mssqlNow = func() time.Time { return time.Date(2026, 10, 11, 13, 14, 16, 0, time.UTC) }
	mssqlServerChallenge = func() ([]byte, error) { return []byte{1, 2, 3, 4, 5, 6, 7, 8}, nil }
	t.Cleanup(func() { mssqlNow, mssqlServerChallenge = prevNow, prevChallenge })
}

func startMSSQL(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	fixMSSQLChallenge(t)
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMSSQL(context.Background(), serverConn, connection.Metadata{TargetPort: 1433}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// finishMSSQL waits for the handler and returns the single produced event.
func finishMSSQL(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedMSSQL) {
	t.Helper()
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	require.Equal(t, "mssql", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedMSSQL)
	require.True(t, ok)
	return produced, events
}

// waitHandlerDone waits for a handler that ends the session itself.
func waitHandlerDone(t *testing.T, done chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not end the session")
	}
}

func readTDS(t *testing.T, conn net.Conn) mssql.Message {
	t.Helper()
	msg, err := mssql.ReadMessage(conn, 1<<16)
	require.NoError(t, err)
	return msg
}

func writeTDS(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	_, err := conn.Write(b)
	require.NoError(t, err)
}

// tdsPacket frames body as one final packet of type typ.
func tdsPacket(typ byte, body []byte) []byte {
	out := []byte{typ, 0x01, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)+mssql.HeaderLen))
	return append(out, body...)
}

// sqlAuthLogin7 builds a TDS 7.4 SQL-auth LOGIN7 packet for user/password.
func sqlAuthLogin7(user, password string) []byte {
	const fixedLen = 94
	fixed := make([]byte, fixedLen)
	binary.LittleEndian.PutUint32(fixed[4:], 0x74000004)
	var vars []byte
	put := func(at int, s string, scramble bool) {
		b := ntlm.EncodeUTF16LE(s)
		if scramble {
			for i, c := range b {
				b[i] = (c<<4 | c>>4) ^ 0xa5
			}
		}
		binary.LittleEndian.PutUint16(fixed[at:], uint16(fixedLen+len(vars)))
		binary.LittleEndian.PutUint16(fixed[at+2:], uint16(len(b)/2))
		vars = append(vars, b...)
	}
	put(36, "WS01", false)
	put(40, user, false)
	put(44, password, true)
	put(48, "OSQL-32", false)
	put(60, "ODBC", false)
	put(68, "master", false)
	body := append(fixed, vars...)
	binary.LittleEndian.PutUint32(body[0:], uint32(len(body)))
	return tdsPacket(mssql.TypeLogin7, body)
}

// ntlmAuthenticate builds a minimal NTLMSSP AUTHENTICATE with an NTLMv2-sized
// NtChallengeResponse.
func ntlmAuthenticate(domain, user, workstation string) []byte {
	msg := make([]byte, 64)
	copy(msg, ntlm.Signature)
	binary.LittleEndian.PutUint32(msg[8:], ntlm.MsgAuthenticate)
	binary.LittleEndian.PutUint32(msg[60:], ntlm.FlagUnicode)
	put := func(at int, b []byte) {
		binary.LittleEndian.PutUint16(msg[at:], uint16(len(b)))
		binary.LittleEndian.PutUint16(msg[at+2:], uint16(len(b)))
		binary.LittleEndian.PutUint32(msg[at+4:], uint32(len(msg)))
		msg = append(msg, b...)
	}
	put(12, nil)
	put(20, make([]byte, 48))
	put(28, ntlm.EncodeUTF16LE(domain))
	put(36, ntlm.EncodeUTF16LE(user))
	put(44, ntlm.EncodeUTF16LE(workstation))
	return msg
}

func expectedChallenge(t *testing.T) []byte {
	t.Helper()
	computer, domain := rdp.Identity()
	sspi := nmapMSSQLLogin7[mssql.HeaderLen+0x9a : mssql.HeaderLen+0x9a+0x21]
	return mssql.BuildSSPIChallenge(sspi, mssql.ChallengeOptions{
		ServerChallenge: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Computer:        computer,
		Domain:          domain,
		ClientFlags:     binary.LittleEndian.Uint32(sspi[12:16]),
		Now:             mssqlNow(),
	})
}

func TestHandleMSSQLNmapNTLMInfo(t *testing.T) {
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, nmapMSSQLPrelogin)
	pre := readTDS(t, client)
	require.Equal(t, mssql.BuildPreloginResponse(), pre.Raw)

	writeTDS(t, client, nmapMSSQLLogin7)
	resp := readTDS(t, client)
	require.Equal(t, byte(mssql.TypeTabular), resp.Type)
	require.Equal(t, byte(0xed), resp.Data[0], "SSPI token")
	challenge := resp.Data[3:]
	require.Equal(t, uint32(ntlm.MsgChallenge), ntlm.MessageType(challenge))
	computer, _ := rdp.Identity()
	require.True(t, bytes.Contains(challenge, ntlm.EncodeUTF16LE(computer)))

	produced, events := finishMSSQL(t, client, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedMSSQL{
		{
			Direction: "read", Command: "prelogin", Payload: nmapMSSQLPrelogin,
			ClientVersion: "8.0.341.0", Encryption: "not_sup", Instance: "MSSQLServer", ThreadID: 0x3132,
		},
		{Direction: "write", Status: "prelogin", Payload: mssql.BuildPreloginResponse()},
		{
			Direction: "read", Command: "login7", Payload: nmapMSSQLLogin7,
			TDSVersion: "0x71000001", Hostname: "Nmap", AppName: "Nmap NSE",
			ServerName: "198.51.100.10", ClientInterface: "mssql.lua",
			IntegratedAuth: true, NTLMType: ntlm.MsgNegotiate,
		},
		{Direction: "write", Status: "sspi-challenge", Payload: expectedChallenge(t)},
	}, events)
}

func TestHandleMSSQLNTLMAuthenticateLoginFailed(t *testing.T) {
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, nmapMSSQLLogin7)
	readTDS(t, client)
	auth := tdsPacket(mssql.TypeSSPI, ntlmAuthenticate("CORP", "svc_sql", "KALI"))
	writeTDS(t, client, auth)
	resp := readTDS(t, client)
	want := mssql.BuildLoginError(mssql.LoginFailed(`CORP\svc_sql`, func() string { c, _ := rdp.Identity(); return c }(), true))
	require.Equal(t, want, resp.Raw)
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	events := produced.decoded.([]parsedMSSQL)
	require.Len(t, events, 4)
	require.Equal(t, parsedMSSQL{
		Direction: "read", Command: "sspi", Payload: auth,
		NTLMType: ntlm.MsgAuthenticate, NTLMDomain: "CORP", NTLMUser: "svc_sql",
		NTLMWorkstation: "KALI", NTLMVersion: "NTLMv2",
	}, events[2])
	require.Equal(t, parsedMSSQL{Direction: "write", Status: "login-failed", Payload: want, ErrorNumber: mssql.ErrLoginFailed}, events[3])
}

func TestHandleMSSQLSQLAuthLoginFailedOmitsPassword(t *testing.T) {
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, nmapMSSQLPrelogin)
	readTDS(t, client)
	login := sqlAuthLogin7("sa", "Hunter2!")
	writeTDS(t, client, login)
	resp := readTDS(t, client)
	computer, _ := rdp.Identity()
	want := mssql.BuildLoginError(mssql.LoginFailed("sa", computer, false))
	require.Equal(t, want, resp.Raw)
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedMSSQL)
	require.Len(t, events, 4)
	require.Equal(t, parsedMSSQL{
		Direction: "read", Command: "login7", Payload: login,
		TDSVersion: "0x74000004", Username: "sa", PasswordSet: true,
		Hostname: "WS01", AppName: "OSQL-32", ClientInterface: "ODBC", Database: "master",
	}, events[2])
	require.Equal(t, mssql.ErrLoginFailed, int(events[3].ErrorNumber))

	out, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(out), "Hunter2!")
	require.NotContains(t, string(out), `"password"`)
}

func TestHandleMSSQLEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, nmapMSSQLPrelogin[:20])
	_, events := finishMSSQL(t, client, hp, done)
	require.Equal(t, []parsedMSSQL{
		{Direction: "read", Command: "prelogin", Payload: nmapMSSQLPrelogin[:20], Truncated: true},
	}, events)
}

func TestHandleMSSQLMalformedHeader(t *testing.T) {
	client, hp, done := startMSSQL(t)

	bad := []byte{0x12, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	writeTDS(t, client, bad)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedMSSQL{
		{Direction: "read", Command: "prelogin", Payload: bad, Truncated: true},
	}, produced.decoded.([]parsedMSSQL))
}

func TestHandleMSSQLMalformedLogin7(t *testing.T) {
	client, hp, done := startMSSQL(t)

	short := tdsPacket(mssql.TypeLogin7, make([]byte, 40))
	writeTDS(t, client, short)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, []parsedMSSQL{
		{Direction: "read", Command: "login7", Payload: short},
	}, produced.decoded.([]parsedMSSQL))
}

func TestHandleMSSQLOversizeIsCapped(t *testing.T) {
	client, hp, done := startMSSQL(t)

	// non-final SQL batch packets past the message cap
	pkt := tdsPacket(mssql.TypeSQLBatch, make([]byte, 4000))
	pkt[1] = 0x00
	go func() {
		for range 40 {
			if _, err := client.Write(pkt); err != nil {
				return
			}
		}
	}()
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	events := produced.decoded.([]parsedMSSQL)
	require.Len(t, events, 1)
	require.True(t, events[0].Truncated)
	require.LessOrEqual(t, len(events[0].Payload), maxMSSQLMessageLen+len(pkt))
}

func TestHandleMSSQLQueryBeforeLoginEndsSession(t *testing.T) {
	client, hp, done := startMSSQL(t)

	batch := tdsPacket(mssql.TypeSQLBatch, ntlm.EncodeUTF16LE("select @@version"))
	writeTDS(t, client, batch)
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, []parsedMSSQL{
		{Direction: "read", Command: "sql_batch", Payload: batch},
	}, produced.decoded.([]parsedMSSQL))
}
