package mongodb

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommandNameFromCapturedFrames(t *testing.T) {
	cases := []struct {
		name string
		b64  string
		cmd  string
		op   int32
	}{
		{
			name: "op_query hello",
			b64:  "OwAAAAEAAAAAAAAA1AcAAAAAAABhZG1pbi4kY21kAAAAAAD/////FAAAAAFoZWxsbwAAAAAAAADwPwA=",
			cmd:  "hello",
			op:   OpQuery,
		},
		{
			name: "op_query isMaster",
			b64:  "PgAAAAIAAAAAAAAA1AcAAAAAAABhZG1pbi4kY21kAAAAAAD/////FwAAAAFpc01hc3RlcgAAAAAAAADwPwA=",
			cmd:  "isMaster",
			op:   OpQuery,
		},
		{
			name: "op_msg hello",
			b64:  "OAAAAAMAAAAAAAAA3QcAAAAAAAAAIwAAAAFoZWxsbwAAAAAAAADwPwIkZGIABgAAAGFkbWluAAA=",
			cmd:  "hello",
			op:   OpMsg,
		},
		{
			name: "op_query buildInfo",
			b64:  "PwAAAGQAAAAAAAAA1AcAAAAAAABhZG1pbi4kY21kAAAAAAD/////GAAAAAFidWlsZEluZm8AAAAAAAAA8D8A",
			cmd:  "buildInfo",
			op:   OpQuery,
		},
		{
			name: "op_msg buildInfo",
			b64:  "PAAAAGUAAAAAAAAA3QcAAAAAAAAAJwAAAAFidWlsZEluZm8AAAAAAAAA8D8CJGRiAAYAAABhZG1pbgAA",
			cmd:  "buildInfo",
			op:   OpMsg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := base64.StdEncoding.DecodeString(tc.b64)
			require.NoError(t, err)
			require.Equal(t, tc.op, int32(binary.LittleEndian.Uint32(msg[12:16])))
			require.Equal(t, tc.cmd, CommandName(tc.op, msg))
		})
	}
}

func TestBuildResponseOpcodeAndFields(t *testing.T) {
	queryHdr := Header{RequestID: 1, OpCode: OpQuery}
	hdr, resp, err := BuildResponse(queryHdr, "hello")
	require.NoError(t, err)
	require.Equal(t, OpReply, hdr.OpCode)
	require.Equal(t, int32(1), hdr.ResponseTo)
	require.Equal(t, int32(2), hdr.RequestID)
	require.Equal(t, int32(len(resp)), hdr.MessageLength)
	require.Contains(t, string(resp), "ismaster")
	require.Contains(t, string(resp), "isWritablePrimary")
	require.Contains(t, string(resp), "maxWireVersion")
	require.Contains(t, string(resp), "minWireVersion")

	msgHdr := Header{RequestID: 3, OpCode: OpMsg}
	hdr, resp, err = BuildResponse(msgHdr, "buildInfo")
	require.NoError(t, err)
	require.Equal(t, OpMsg, hdr.OpCode)
	require.Equal(t, int32(3), hdr.ResponseTo)
	require.Contains(t, string(resp), "version")
	require.Contains(t, string(resp), "versionArray")
	require.Contains(t, string(resp), "7.0.0")

	hdr, resp, err = BuildResponse(Header{RequestID: 9, OpCode: OpMsg}, "ping")
	require.NoError(t, err)
	require.Equal(t, OpMsg, hdr.OpCode)
	require.NotContains(t, string(resp), "ismaster")
	require.Contains(t, string(resp), "ok")
}

func TestWrapHelpersRoundTripCommand(t *testing.T) {
	q := WrapOpQuery(1, "admin.$cmd", CmdDoc("hello"))
	require.Equal(t, "hello", CommandName(OpQuery, q))

	m := WrapOpMsg(3, CmdDoc("isMaster", StringField("$db", "admin")))
	require.Equal(t, "isMaster", CommandName(OpMsg, m))
}
