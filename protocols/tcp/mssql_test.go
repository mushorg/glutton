package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/mssql"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
	"github.com/spf13/viper"
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

// useMSSQLRecall swaps mssqlRecall for store for the duration of the test.
func useMSSQLRecall(t *testing.T, store *recall.Store) {
	t.Helper()
	old := mssqlRecall
	mssqlRecall = store
	t.Cleanup(func() { mssqlRecall = old })
}

func startMSSQL(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	useMSSQLRecall(t, recall.New(recall.DefaultConfig()))
	return startMSSQLSession(t)
}

// startMSSQLSession starts one more session against the current mssqlRecall.
func startMSSQLSession(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
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
	require.Equal(t, parsedMSSQL{Direction: "write", Status: "login-failed", Payload: want, ErrorNumber: mssql.ErrLoginFailed, Visit: 1}, events[3])
}

func TestHandleMSSQLSQLAuthLoginFailedRecordsPassword(t *testing.T) {
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
		TDSVersion: "0x74000004", Username: "sa", Password: "Hunter2!",
		Hostname: "WS01", AppName: "OSQL-32", ClientInterface: "ODBC", Database: "master",
	}, events[2])
	require.Equal(t, mssql.ErrLoginFailed, int(events[3].ErrorNumber))

	out, err := json.Marshal(events)
	require.NoError(t, err)
	require.Contains(t, string(out), `"password":"Hunter2!"`)
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

// SQL Server sa brute forcer from Ochi event
// 6d407890-15ba-4288-beca-3dd90aa09bd4: PRELOGIN (8.0.341.0, encryption off),
// then a TDS 7.1 SQL-auth LOGIN7 sa/15091970 (OLEDB, client ID
// 08:00:27:ff:ff:ff). The tool opens one connection per guess. Ochi scrubbed
// the 15-character sensor address in ServerName to 1.2.3.4 without fixing the
// lengths, so it is replaced by a placeholder of the original length.
var (
	bruteMSSQLPrelogin = mustDecodeHex("120100340000000000001500060100" + "1b00010200" +
		"1c000c0300280004ff080001550000004d5353514c536572766572" + "00280c0000")
	bruteMSSQLLogin7 = mustDecodeHex("100100c200000100ba0000000100007100100000000000072c06000000000000" +
		"e003100820feffff0408000056000a006a0002006e0008007e000a0092000f00" +
		"00000000b0000500b0000000b0000000080027ffffff00000000a00000006c00" +
		"35003400740039007500700074007100730073006100b6a5f6a5a6a536a5b6a5" +
		"36a5d6a5a6a56f0076006d0067006a006a006300700030003400310039003200" +
		"2e0030002e0032002e00310030002c0031003400330033004f004c0045004400" +
		"4200")
)

// bruteMSSQLLogin7Read is the decoded read frame of bruteMSSQLLogin7.
func bruteMSSQLLogin7Read() parsedMSSQL {
	return parsedMSSQL{
		Direction: "read", Command: "login7", Payload: bruteMSSQLLogin7,
		TDSVersion: "0x71000001", Username: "sa", Password: "15091970",
		Hostname: "l54t9uptqs", AppName: "ovmgjjcp04", ServerName: "192.0.2.10,1433",
		ClientInterface: "OLEDB", ClientID: "08:00:27:ff:ff:ff",
	}
}

// bruteMSSQLLogin sends the captured PRELOGIN and LOGIN7 and returns the
// login reply.
func bruteMSSQLLogin(t *testing.T, client net.Conn) mssql.Message {
	t.Helper()
	writeTDS(t, client, bruteMSSQLPrelogin)
	readTDS(t, client)
	writeTDS(t, client, bruteMSSQLLogin7)
	return readTDS(t, client)
}

// sqlBatch74 frames query as a TDS 7.2+ SQL_BATCH with an ALL_HEADERS
// transaction descriptor, in 4096-byte packets.
func sqlBatch74(query string) []byte {
	body := binary.LittleEndian.AppendUint32(nil, 22)
	body = binary.LittleEndian.AppendUint32(body, 18)
	body = binary.LittleEndian.AppendUint16(body, 2)
	body = append(body, make([]byte, 8)...)
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = append(body, ntlm.EncodeUTF16LE(query)...)
	const chunk = 4096 - mssql.HeaderLen
	var out []byte
	for len(body) > chunk {
		pkt := tdsPacket(mssql.TypeSQLBatch, body[:chunk])
		pkt[1] = 0x00
		out = append(out, pkt...)
		body = body[chunk:]
	}
	return append(out, tdsPacket(mssql.TypeSQLBatch, body)...)
}

func setMSSQLViper(t *testing.T, key string, value any) {
	t.Helper()
	viper.Set(key, value)
	t.Cleanup(func() { viper.Set(key, nil) })
}

func TestHandleMSSQLBruteForceAcceptedAfterFailures(t *testing.T) {
	useMSSQLRecall(t, recall.New(recall.DefaultConfig()))
	computer, _ := rdp.Identity()
	failed := mssql.BuildLoginError(mssql.LoginFailed("sa", computer, true))

	// one guess per connection, as the tool does: the first three fail
	for range mssqlAcceptAfter {
		client, hp, done := startMSSQLSession(t)
		require.Equal(t, failed, bruteMSSQLLogin(t, client).Raw)
		waitHandlerDone(t, done)
		events := waitProduced(t, hp).decoded.([]parsedMSSQL)
		require.Len(t, events, 4)
		require.Equal(t, parsedMSSQL{Direction: "write", Status: "login-failed", Payload: failed, ErrorNumber: mssql.ErrLoginFailed, Visit: 1}, events[3])
	}

	client, hp, done := startMSSQLSession(t)
	ack := mssql.BuildLoginAck(mssql.LoginAckOptions{TDSVersion: 0x71000001, PacketSize: 4096, Server: computer})
	require.Equal(t, ack, bruteMSSQLLogin(t, client).Raw)

	opts := mssql.QueryOptions{TDSVersion: 0x71000001, Server: computer}
	version := tdsPacket(mssql.TypeSQLBatch, ntlm.EncodeUTF16LE("select @@version"))
	writeTDS(t, client, version)
	versionResp, status := mssql.BuildBatchReply("select @@version", opts)
	require.Equal(t, mssql.StatusResult, status)
	require.Equal(t, versionResp, readTDS(t, client).Raw)

	const enable = "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
	configure := tdsPacket(mssql.TypeSQLBatch, ntlm.EncodeUTF16LE(enable))
	writeTDS(t, client, configure)
	configureResp, _ := mssql.BuildBatchReply(enable, opts)
	require.Equal(t, configureResp, readTDS(t, client).Raw)

	const cmd = "exec master..xp_cmdshell 'whoami'"
	shell := tdsPacket(mssql.TypeSQLBatch, ntlm.EncodeUTF16LE(cmd))
	writeTDS(t, client, shell)
	shellResp, _ := mssql.BuildBatchReply(cmd, opts)
	require.Equal(t, shellResp, readTDS(t, client).Raw)

	_, events := finishMSSQL(t, client, hp, done)
	require.Equal(t, []parsedMSSQL{
		{Direction: "read", Command: "prelogin", Payload: bruteMSSQLPrelogin, ClientVersion: "8.0.341.0", Encryption: "off", Instance: "MSSQLServer", ThreadID: 671875072},
		{Direction: "write", Status: "prelogin", Payload: mssql.BuildPreloginResponse()},
		bruteMSSQLLogin7Read(),
		{Direction: "write", Status: "login-ok", Payload: ack, Visit: 1},
		{Direction: "read", Command: "sql_batch", Payload: version, Query: "select @@version"},
		{Direction: "write", Status: "result", Payload: versionResp},
		{Direction: "read", Command: "sql_batch", Payload: configure, Query: enable},
		{Direction: "write", Status: "done", Payload: configureResp},
		{Direction: "read", Command: "sql_batch", Payload: shell, Query: cmd},
		{Direction: "write", Status: "result", Payload: shellResp},
	}, events)
}

func TestHandleMSSQLAcceptLoginsDisabled(t *testing.T) {
	useMSSQLRecall(t, recall.New(recall.DefaultConfig()))
	setMSSQLViper(t, "mssql.accept_logins", false)
	setMSSQLViper(t, "mssql.accept_after", 0)

	client, _, done := startMSSQLSession(t)
	resp := bruteMSSQLLogin(t, client)
	require.Equal(t, byte(0xaa), resp.Data[0], "ERROR token")
	waitHandlerDone(t, done)
}

func TestHandleMSSQLAcceptWithRecallDisabled(t *testing.T) {
	useMSSQLRecall(t, recall.New(recall.Config{}))
	setMSSQLViper(t, "mssql.accept_after", 0)

	client, hp, done := startMSSQLSession(t)
	resp := bruteMSSQLLogin(t, client)
	require.Equal(t, byte(0xe3), resp.Data[0], "ENVCHANGE starts the LOGINACK stream")
	_, events := finishMSSQL(t, client, hp, done)
	require.Equal(t, "login-ok", events[3].Status)
}

func TestHandleMSSQLRPCAndAttention(t *testing.T) {
	setMSSQLViper(t, "mssql.accept_after", 0)
	client, hp, done := startMSSQL(t)
	computer, _ := rdp.Identity()

	writeTDS(t, client, sqlAuthLogin7("sa", "sa"))
	ack := readTDS(t, client)
	require.Equal(t, mssql.BuildLoginAck(mssql.LoginAckOptions{TDSVersion: 0x74000004, Database: "master", Server: computer}), ack.Raw)

	// sp_executesql by ProcID with an NVARCHAR(4000) statement
	stmt := ntlm.EncodeUTF16LE("SELECT @@SERVERNAME")
	body := binary.LittleEndian.AppendUint32(nil, 22)
	body = binary.LittleEndian.AppendUint32(body, 18)
	body = binary.LittleEndian.AppendUint16(body, 2)
	body = append(body, make([]byte, 8)...)
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = append(body, 0xff, 0xff, 10, 0, 0, 0) // ProcID sp_executesql, OptionFlags
	body = append(body, 0, 0, 0xe7, 0x40, 0x1f, 0x09, 0x04, 0xd0, 0x00, 0x34)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(stmt)))
	body = append(body, stmt...)
	rpc := tdsPacket(mssql.TypeRPC, body)
	writeTDS(t, client, rpc)
	opts := mssql.QueryOptions{TDSVersion: 0x74000004, Server: computer}
	rpcResp, status := mssql.BuildRPCReply("SELECT @@SERVERNAME", opts)
	require.Equal(t, mssql.StatusResult, status)
	require.Equal(t, rpcResp, readTDS(t, client).Raw)

	attn := tdsPacket(mssql.TypeAttention, nil)
	writeTDS(t, client, attn)
	require.Equal(t, mssql.BuildAttentionAck(0x74000004), readTDS(t, client).Raw)

	_, events := finishMSSQL(t, client, hp, done)
	require.Len(t, events, 6)
	require.Equal(t, parsedMSSQL{Direction: "read", Command: "sp_executesql", Payload: rpc, Query: "SELECT @@SERVERNAME"}, events[2])
	require.Equal(t, parsedMSSQL{Direction: "write", Status: "result", Payload: rpcResp}, events[3])
	require.Equal(t, parsedMSSQL{Direction: "read", Command: "attention", Payload: attn}, events[4])
	require.Equal(t, parsedMSSQL{Direction: "write", Status: "attention", Payload: mssql.BuildAttentionAck(0x74000004)}, events[5])
}

func TestHandleMSSQLStoresLongQuery(t *testing.T) {
	setMSSQLViper(t, "mssql.accept_after", 0)
	var stored []byte
	prev := mssqlStore
	mssqlStore = func(data []byte, folder string) (string, error) {
		require.Equal(t, filepath.Join("payloads", "mssql"), folder)
		stored = data
		return "hash", nil
	}
	t.Cleanup(func() { mssqlStore = prev })
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, sqlAuthLogin7("sa", "sa"))
	readTDS(t, client)
	query := "CREATE ASSEMBLY x FROM 0x4D5A" + strings.Repeat("00", maxMSSQLMessageLen/2)
	writeTDS(t, client, sqlBatch74(query))
	readTDS(t, client)

	_, events := finishMSSQL(t, client, hp, done)
	require.Equal(t, []byte(query), stored)
	read := events[2]
	require.Equal(t, "hash", read.PayloadHash)
	require.True(t, read.Truncated)
	require.Equal(t, query[:maxMSSQLQuery], read.Query)
	require.Len(t, read.Payload, maxMSSQLMessageLen, "recorded payload is capped")
}

func TestHandleMSSQLLoginAfterLoginEndsSession(t *testing.T) {
	setMSSQLViper(t, "mssql.accept_after", 0)
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, sqlAuthLogin7("sa", "sa"))
	readTDS(t, client)
	writeTDS(t, client, nmapMSSQLPrelogin)
	waitHandlerDone(t, done)
	events := waitProduced(t, hp).decoded.([]parsedMSSQL)
	require.Len(t, events, 3)
	require.Equal(t, "prelogin", events[2].Command)
}

func TestHandleMSSQLRequestCap(t *testing.T) {
	setMSSQLViper(t, "mssql.accept_after", 0)
	client, hp, done := startMSSQL(t)

	writeTDS(t, client, sqlAuthLogin7("sa", "sa"))
	readTDS(t, client)
	batch := sqlBatch74("select 1")
	for range maxMSSQLRequests {
		writeTDS(t, client, batch)
		readTDS(t, client)
	}
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	require.Len(t, produced.decoded.([]parsedMSSQL), 2+2*maxMSSQLRequests)
}
