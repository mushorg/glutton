package oncrpc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func nfsWords(v ...uint32) []byte {
	e := &encoder{}
	e.u32(v...)
	return e.b
}

func TestNFSCommand(t *testing.T) {
	require.Equal(t, "NFSPROC3_GETATTR", NFSCommand(&Call{Program: ProgNFS, Version: 3, Procedure: 1}))
	require.Equal(t, "NFSPROC4_COMPOUND", NFSCommand(&Call{Program: ProgNFS, Version: 4, Procedure: 1}))
	require.Equal(t, "NFSPROC3_99", NFSCommand(&Call{Program: ProgNFS, Version: 3, Procedure: 99}))
	require.Equal(t, "NFSPROC_0", NFSCommand(&Call{Program: ProgNFS, Version: 2}))
	require.Equal(t, "CALL", NFSCommand(&Call{Program: 100005}))
	require.Equal(t, "REPLY", NFSCommand(&Call{MsgType: MsgReply}))
}

func TestReplyNFS(t *testing.T) {
	call := func(vers, proc uint32, args ...uint32) *Call {
		return &Call{XID: 7, RPCVersion: 2, Program: ProgNFS, Version: vers, Procedure: proc, Args: nfsWords(args...)}
	}

	body, status := ReplyNFS(call(3, 0))
	require.Equal(t, "SUCCESS", status)
	require.Equal(t, nfsWords(7, 1, 0, 0, 0, 0), body)

	body, status = ReplyNFS(call(2, 0))
	require.Equal(t, "PROG_MISMATCH", status)
	require.Equal(t, nfsWords(7, 1, 0, 0, 0, 2, 3, 4), body)

	body, status = ReplyNFS(call(4, 1, 0, 3, 1)) // minor version 3
	require.Equal(t, "SUCCESS", status)
	require.Equal(t, nfsWords(7, 1, 0, 0, 0, 0, 10021, 0, 0), body)

	_, status = ReplyNFS(call(4, 1)) // no COMPOUND args
	require.Equal(t, "GARBAGE_ARGS", status)

	_, status = ReplyNFS(call(4, 5))
	require.Equal(t, "PROC_UNAVAIL", status)

	body, status = ReplyNFS(&Call{XID: 7, RPCVersion: 1, Program: ProgNFS})
	require.Equal(t, "RPC_MISMATCH", status)
	require.Equal(t, nfsWords(7, 1, 1, 0, 2, 2), body)

	body, status = ReplyNFS(&Call{MsgType: MsgReply})
	require.Nil(t, body)
	require.Empty(t, status)
}
