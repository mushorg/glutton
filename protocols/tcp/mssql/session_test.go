package mssql

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/stretchr/testify/require"
)

// lengthTokens splits a token stream of length-prefixed tokens and DONE
// tokens, as a login reply is; doneLen is 9 (TDS 7.1) or 13.
func lengthTokens(t *testing.T, b []byte, doneLen int) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		n := doneLen
		if b[0] != tokenDone {
			require.GreaterOrEqual(t, len(b), 3)
			n = 3 + int(binary.LittleEndian.Uint16(b[1:3]))
		}
		require.GreaterOrEqual(t, len(b), n)
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

func TestBuildLoginAck(t *testing.T) {
	for _, tc := range []struct {
		client, ack uint32
		doneLen     int
	}{
		{0x71000001, 0x71000001, 9},
		{0x74000004, 0x74000004, 13},
	} {
		resp := BuildLoginAck(LoginAckOptions{TDSVersion: tc.client, PacketSize: 8000, Server: "WIN-ABCDEFGHIJK"})
		require.Equal(t, byte(TypeTabular), resp[0])
		require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))
		toks := lengthTokens(t, resp[HeaderLen:], tc.doneLen)
		var types []byte
		for _, tok := range toks {
			types = append(types, tok[0])
		}
		require.Equal(t, []byte{tokenEnvChange, tokenInfo, tokenEnvChange, tokenEnvChange, tokenInfo, tokenLoginAck, tokenEnvChange, tokenDone}, types)

		require.Equal(t, append(append([]byte{tokenEnvChange, 0x1b, 0x00, envDatabase}, bVarChar("master")...), bVarChar("master")...), toks[0])
		require.Contains(t, string(toks[1]), string(ntlm.EncodeUTF16LE("Changed database context to 'master'.")))
		require.Equal(t, []byte{tokenEnvChange, 0x08, 0x00, envCollation, 0x05, 0x09, 0x04, 0xd0, 0x00, 0x34, 0x00}, toks[2])
		require.Contains(t, string(toks[4]), string(ntlm.EncodeUTF16LE("Changed language setting to us_english.")))

		ack := toks[5][3:]
		require.Equal(t, byte(1), ack[0], "SQL interface")
		require.Equal(t, tc.ack, binary.BigEndian.Uint32(ack[1:5]))
		require.Equal(t, bVarChar(progName), ack[5:5+1+22*2])
		require.Equal(t, []byte{0x0f, 0x00, 0x07, 0xd0}, ack[len(ack)-4:])

		require.Equal(t, append(append([]byte{tokenEnvChange, 0x13, 0x00, envPacketSize}, bVarChar("8000")...), bVarChar("4096")...), toks[6])
		require.Equal(t, uint16(0), binary.LittleEndian.Uint16(toks[7][1:3]), "final DONE")
	}
}

func TestBuildLoginAckDefaults(t *testing.T) {
	resp := BuildLoginAck(LoginAckOptions{TDSVersion: 0x74000004, PacketSize: 100000, Database: "msdb", Language: "Deutsch"})
	require.True(t, bytes.Contains(resp, bVarChar("msdb")))
	require.True(t, bytes.Contains(resp, ntlm.EncodeUTF16LE("Changed language setting to Deutsch.")))
	require.True(t, bytes.Contains(resp, append([]byte{envPacketSize}, bVarChar("4096")...)))
}

func TestAckTDSVersion(t *testing.T) {
	require.Equal(t, uint32(0x74000004), AckTDSVersion(0x74000004))
	require.Equal(t, uint32(0x74000004), AckTDSVersion(0x75000000))
	require.Equal(t, uint32(0x72090002), AckTDSVersion(0x72090002))
	require.Equal(t, uint32(0x71000001), AckTDSVersion(0x71000001))
	require.Equal(t, uint32(0x70000000), AckTDSVersion(0x70000000))
}

// lastDoneStatus returns the status of the final DONE-type token.
func lastDoneStatus(resp []byte, legacy bool) uint16 {
	n := 13
	if legacy {
		n = 9
	}
	return binary.LittleEndian.Uint16(resp[len(resp)-n+1:])
}

func TestBuildBatchReply(t *testing.T) {
	opts := QueryOptions{TDSVersion: 0x74000004, Server: "WIN-ABCDEFGHIJK"}
	for _, tc := range []struct {
		query    string
		status   string
		contains []string
		final    byte
	}{
		{"SELECT @@VERSION", StatusResult, []string{Version}, tokenDone},
		{"select @@servername", StatusResult, []string{"WIN-ABCDEFGHIJK"}, tokenDone},
		{
			"EXEC sp_configure 'show advanced',1;RECONFIGURE;exec sp_configure N'Ole Automation', 1;",
			StatusDone,
			[]string{
				"Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.",
				"Configuration option 'Ole Automation Procedures' changed from 0 to 1. Run the RECONFIGURE statement to install.",
			},
			tokenDoneProc,
		},
		{"exec sp_configure 'xp_cmdshell', 0", StatusDone, []string{"changed from 1 to 0"}, tokenDoneProc},
		{"exec master..xp_cmdshell 'cmd /c whoami'", StatusResult, []string{"output", cmdShellUser}, tokenDoneProc},
		{"EXEC xp_cmdshell 'hostname.exe'", StatusResult, []string{"WIN-ABCDEFGHIJK"}, tokenDoneProc},
		{"use master; create table t(x int)", StatusDone, nil, tokenDone},
	} {
		resp, status := BuildBatchReply(tc.query, opts)
		require.Equal(t, tc.status, status, tc.query)
		require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])), tc.query)
		for _, s := range tc.contains {
			require.True(t, bytes.Contains(resp, ntlm.EncodeUTF16LE(s)), "%q lacks %q", tc.query, s)
		}
		require.Equal(t, tc.final, resp[len(resp)-13], tc.query)
		require.Zero(t, lastDoneStatus(resp, false)&doneMore, "final token ends the batch: %q", tc.query)
	}
}

func TestBuildBatchReplyLegacy(t *testing.T) {
	resp, _ := BuildBatchReply("exec xp_cmdshell 'dir'", QueryOptions{TDSVersion: 0x71000001})
	// COLMETADATA with a 2-byte UserType, the NULL row, then DONEINPROC,
	// RETURNSTATUS and DONEPROC with 4-byte row counts
	body := resp[HeaderLen:]
	require.Equal(t, []byte{tokenColMetadata, 1, 0, 0, 0, 1, 0, typeNVarChar, 0xfe, 0x01}, body[:10])
	tail := body[len(body)-(3+9+5+9):]
	require.Equal(t, []byte{tokenRow, 0xff, 0xff}, tail[:3])
	require.Equal(t, byte(tokenDoneInProc), tail[3])
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(tail[3+5:]))
	require.Equal(t, []byte{tokenReturnStatus, 0, 0, 0, 0}, tail[12:17])
	require.Equal(t, byte(tokenDoneProc), tail[17])
	require.Zero(t, lastDoneStatus(resp, true))
}

func TestBuildRPCReply(t *testing.T) {
	resp, status := BuildRPCReply("", QueryOptions{TDSVersion: 0x74000004})
	require.Equal(t, StatusDone, status)
	require.Equal(t, append([]byte{tokenReturnStatus, 0, 0, 0, 0, tokenDoneProc}, make([]byte, 12)...), resp[HeaderLen:])

	resp, status = BuildRPCReply("select @@version", QueryOptions{TDSVersion: 0x74000004})
	require.Equal(t, StatusResult, status)
	require.True(t, bytes.Contains(resp, ntlm.EncodeUTF16LE(Version)))
	require.Equal(t, byte(tokenDoneProc), resp[len(resp)-13])
	require.Zero(t, lastDoneStatus(resp, false))
}

func TestBuildAttentionAckAndDone(t *testing.T) {
	require.Equal(t, []byte{tokenDone, doneAttn, 0, 0, 0, 0, 0, 0, 0}, BuildAttentionAck(0x71000001)[HeaderLen:])
	require.Equal(t, append([]byte{tokenDone}, make([]byte, 12)...), BuildDone(0x74000004)[HeaderLen:])
}

// allHeaders is a TDS 7.2+ ALL_HEADERS block with a transaction descriptor.
func allHeaders() []byte {
	b := binary.LittleEndian.AppendUint32(nil, 22)
	b = binary.LittleEndian.AppendUint32(b, 18)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = append(b, make([]byte, 8)...)
	return binary.LittleEndian.AppendUint32(b, 1)
}

func TestParseSQLBatch(t *testing.T) {
	q := ntlm.EncodeUTF16LE("select @@version")
	require.Equal(t, "select @@version", ParseSQLBatch(q))
	require.Equal(t, "select @@version", ParseSQLBatch(append(allHeaders(), q...)))
	require.Equal(t, "select @@version", ParseSQLBatch(append(q, 0x41)), "odd trailing byte")
	// a broken ALL_HEADERS is kept as text rather than dropped
	bad := allHeaders()
	binary.LittleEndian.PutUint16(bad[8:], 9)
	require.Len(t, ParseSQLBatch(append(bad, q...)), len(bad)/2+len("select @@version"))
	require.Empty(t, ParseSQLBatch(nil))
}

// rpcParam is an NVARCHAR parameter of an RPC request.
func rpcParam(value string, plp bool) []byte {
	v := ntlm.EncodeUTF16LE(value)
	b := []byte{0, 0, typeNVarChar}
	if plp {
		b = append(b, 0xff, 0xff)
		b = append(b, collation...)
		b = binary.LittleEndian.AppendUint64(b, uint64(len(v)))
		half := len(v) / 2
		b = binary.LittleEndian.AppendUint32(b, uint32(half))
		b = append(b, v[:half]...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(v)-half))
		b = append(b, v[half:]...)
		return binary.LittleEndian.AppendUint32(b, 0)
	}
	b = append(b, 0x40, 0x1f)
	b = append(b, collation...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func TestParseRPC(t *testing.T) {
	byID := append(allHeaders(), 0xff, 0xff, 10, 0, 0, 0)
	require.Equal(t, RPC{Proc: "sp_executesql", Statement: "select 1"}, ParseRPC(append(byID, rpcParam("select 1", false)...)))
	require.Equal(t, RPC{Proc: "sp_executesql", Statement: "select 2"}, ParseRPC(append(byID, rpcParam("select 2", true)...)))

	name := ntlm.EncodeUTF16LE("sp_executesql")
	byName := append(binary.LittleEndian.AppendUint16(nil, uint16(len(name)/2)), name...)
	byName = append(byName, 0, 0)
	require.Equal(t, RPC{Proc: "sp_executesql", Statement: "x"}, ParseRPC(append(byName, rpcParam("x", false)...)))

	other := ntlm.EncodeUTF16LE("xp_dirtree")
	require.Equal(t, RPC{Proc: "xp_dirtree"}, ParseRPC(append(append([]byte{byte(len(other) / 2), 0}, other...), 0, 0)))
	require.Equal(t, RPC{Proc: "sp_prepexec"}, ParseRPC([]byte{0xff, 0xff, 13, 0, 0, 0}))
	require.Equal(t, RPC{Proc: "proc_99"}, ParseRPC([]byte{0xff, 0xff, 99, 0}))

	// every truncation of a valid request parses without panicking
	full := append(byID, rpcParam("select 1", true)...)
	for i := range full {
		ParseRPC(full[:i])
	}
}

func TestLooksLikeBinaryBlob(t *testing.T) {
	require.True(t, LooksLikeBinaryBlob("CREATE ASSEMBLY a FROM 0x4D5A90000300"))
	require.True(t, LooksLikeBinaryBlob("declare @b varchar(max)='TVqQAAMAAAAEAAAA//8AALgA'"))
	require.False(t, LooksLikeBinaryBlob("select @@version"))
}
