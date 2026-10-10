package adb

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// cnxnHost is the CNXN a v1 adb client (and most 5555 scanners) opens with:
// version 0x01000000, maxdata 4096, "host::\0". Synthetic, built from
// protocol.txt.
var cnxnHost, _ = hex.DecodeString(
	"434e584e" + "00000001" + "00100000" + "07000000" + "32020000" + "bcb1a7b1" +
		"686f73743a3a00")

func TestBuildMatchesWire(t *testing.T) {
	require.Equal(t, cnxnHost, Build(CmdCNXN, 0x01000000, 4096, []byte("host::\x00")))
}

func TestReadMessage(t *testing.T) {
	m, raw, err := ReadMessage(bytes.NewReader(cnxnHost), MaxPayload)
	require.NoError(t, err)
	require.Equal(t, cnxnHost, raw)
	require.Equal(t, "CNXN", m.Name())
	require.Equal(t, uint32(0x01000000), m.Arg0)
	require.Equal(t, uint32(4096), m.Arg1)
	require.Equal(t, Checksum(m.Data), m.DataCheck)
	require.Equal(t, "host::", SystemIdentity(m.Data))
}

func TestReadMessageErrors(t *testing.T) {
	_, raw, err := ReadMessage(bytes.NewReader(cnxnHost[:10]), MaxPayload)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, cnxnHost[:10], raw)

	_, raw, err = ReadMessage(bytes.NewReader(cnxnHost[:27]), MaxPayload)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, cnxnHost[:27], raw)

	bad := bytes.Clone(cnxnHost)
	bad[20] ^= 0xff
	_, raw, err = ReadMessage(bytes.NewReader(bad), MaxPayload)
	require.ErrorIs(t, err, ErrBadMagic)
	require.Len(t, raw, HeaderLen)

	_, raw, err = ReadMessage(bytes.NewReader(cnxnHost), 6)
	require.ErrorIs(t, err, ErrTooLarge)
	require.Len(t, raw, HeaderLen)
}

func TestLooksLikeADB(t *testing.T) {
	require.True(t, LooksLikeADB(cnxnHost[:8]))
	require.True(t, LooksLikeADB([]byte("000chost:version")))
	require.False(t, LooksLikeADB([]byte("GET / HTTP/1.1")))
	require.False(t, LooksLikeADB([]byte("1234abcd")))
	require.False(t, LooksLikeADB([]byte("OPEN")))
	require.False(t, LooksLikeADB([]byte("CNX")))
}

func TestSplitService(t *testing.T) {
	for _, tc := range []struct{ in, name, arg string }{
		{"shell:cd /data/local/tmp; id\x00", "shell", "cd /data/local/tmp; id"},
		{"shell:\x00", "shell", ""},
		{"shell,v2,raw:ls\x00", "shell", "ls"},
		{"sync:\x00", "sync", ""},
		{"tcp:10.0.0.1:80\x00", "tcp", "10.0.0.1:80"},
		{"jdwp\x00", "jdwp", ""},
	} {
		name, arg := SplitService([]byte(tc.in))
		require.Equal(t, tc.name, name, tc.in)
		require.Equal(t, tc.arg, arg, tc.in)
	}
}

func syncReq(id string, body []byte) []byte {
	return append(syncHeader(id, uint32(len(body))), body...)
}

func TestSyncParserSplitAndBatched(t *testing.T) {
	stream := bytes.Join([][]byte{
		syncReq("STAT", []byte("/data/local/tmp/x")),
		syncReq("SEND", []byte("/data/local/tmp/x,33206")),
		syncReq("DATA", []byte("\x7fELF")),
		syncReq("DATA", []byte("rest")),
		syncHeader("DONE", 1546300800),
		syncHeader("QUIT", 0),
	}, nil)

	var p SyncParser
	var reqs []SyncRequest
	// feed one byte at a time: requests split across WRTE payloads
	for i := range stream {
		got, err := p.Feed(stream[i : i+1])
		require.NoError(t, err)
		reqs = append(reqs, got...)
	}
	require.Equal(t, []SyncRequest{
		{ID: "STAT", Path: "/data/local/tmp/x"},
		{ID: "SEND", Path: "/data/local/tmp/x", Mode: "33206"},
		{ID: "DATA", Data: []byte("\x7fELF")},
		{ID: "DATA", Data: []byte("rest")},
		{ID: "DONE", Mtime: 1546300800},
		{ID: "QUIT"},
	}, reqs)

	var batched SyncParser
	got, err := batched.Feed(stream)
	require.NoError(t, err)
	require.Equal(t, reqs, got)
}

func TestSyncParserRejects(t *testing.T) {
	var p SyncParser
	_, err := p.Feed(syncHeader("DATA", SyncDataMax+1))
	require.ErrorIs(t, err, ErrSyncRequest)

	p = SyncParser{}
	_, err = p.Feed(syncHeader("SEND", SyncPathMax+1))
	require.ErrorIs(t, err, ErrSyncRequest)

	p = SyncParser{}
	_, err = p.Feed(syncHeader("STA2", 4))
	require.ErrorIs(t, err, ErrSyncRequest)
}

func TestSyncReplies(t *testing.T) {
	require.Equal(t, []byte("OKAY\x00\x00\x00\x00"), SyncOkay())
	require.Equal(t, []byte("FAIL\x04\x00\x00\x00nope"), SyncFail("nope"))
	require.Equal(t, append([]byte("STAT"), 0xf9, 0x41, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0), SyncStat(0o40771, 4096, 0))
	require.Equal(t, append([]byte("DONE"), make([]byte, 16)...), SyncListDone())
}
