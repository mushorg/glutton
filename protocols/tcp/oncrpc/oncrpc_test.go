package oncrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Shodan PMAPPROC_DUMP over TCP (Ochi event c6b98aad-61b0-4449-ac2c-88d5cdd4b111).
var shodanDump = mustHex("80000028e877bb11000000000000000200" + "0186a0000000020000000400000000000000000000000000000000")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func be(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return b
}

func xdrStr(s string) []byte {
	e := &encoder{}
	e.str(s)
	return e.b
}

func call(prog, vers, proc uint32, args ...[]byte) []byte {
	b := be(0x01020304, MsgCall, 2, prog, vers, proc, 0, 0, 0, 0)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}

func testEnv() Env {
	return Env{Mappings: Mappings([]byte("198.51.100.1")), LocalIP: net.ParseIP("198.51.100.1"), Now: time.Unix(1760205696, 0)}
}

// pmaplist decodes a v2 DUMP result.
func pmaplist(t *testing.T, b []byte) []Mapping {
	t.Helper()
	d := &decoder{b: b}
	var out []Mapping
	for {
		more, err := d.u32()
		require.NoError(t, err)
		if more == 0 {
			require.Equal(t, len(b), d.off, "no trailing bytes")
			return out
		}
		v := make([]uint32, 4)
		for i := range v {
			v[i], err = d.u32()
			require.NoError(t, err)
		}
		out = append(out, Mapping{Program: v[0], Version: v[1], Prot: v[2], Port: uint16(v[3])})
	}
}

func TestReadRecordAndParseShodanDump(t *testing.T) {
	raw, body, truncated, err := ReadRecord(bytes.NewReader(shodanDump), 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, shodanDump, raw)
	require.Equal(t, shodanDump[4:], body)

	c, err := Parse(body)
	require.NoError(t, err)
	require.Equal(t, &Call{XID: 0xe877bb11, MsgType: MsgCall, RPCVersion: 2, Program: ProgPortmap, Version: 2, Procedure: 4, Args: []byte{}, Header: true, Cred: true}, c)
	require.Equal(t, "PMAPPROC_DUMP", c.Command())
	require.Equal(t, "AUTH_NONE", AuthName(c.CredFlavor))
}

func TestReplyDumpV2(t *testing.T) {
	c, err := Parse(shodanDump[4:])
	require.NoError(t, err)
	env := testEnv()
	body, status := Reply(c, env)
	require.Equal(t, "SUCCESS", status)
	require.Equal(t, be(0xe877bb11, MsgReply, 0, 0, 0, 0), body[:24], "echoed XID, MSG_ACCEPTED, AUTH_NONE verf, SUCCESS")

	list := pmaplist(t, body[24:])
	require.Len(t, list, 8)
	require.Equal(t, Mapping{Program: ProgPortmap, Version: 4, Prot: ProtTCP, Port: 111}, list[0])
	require.Equal(t, Mapping{Program: ProgPortmap, Version: 2, Prot: ProtUDP, Port: 111}, list[5])
	require.Equal(t, uint32(ProgStatus), list[6].Program)
	require.Equal(t, env.Mappings[6].Port, list[6].Port)
	require.Less(t, len(body), 200)

	framed := Frame(body)
	require.Equal(t, uint32(0x80000000|len(body)), binary.BigEndian.Uint32(framed))
}

func TestMappingsStablePerSeed(t *testing.T) {
	a, b := Mappings([]byte("198.51.100.1")), Mappings([]byte("198.51.100.1"))
	require.Equal(t, a, b)
	other := Mappings([]byte("203.0.113.9"))
	require.NotEqual(t, a[6].Port, other[6].Port)
	for _, m := range [][]Mapping{a, other} {
		require.GreaterOrEqual(t, m[6].Port, uint16(32768))
		require.NotEqual(t, m[6].Port, m[7].Port)
	}
}

func TestReplyGetPortV2(t *testing.T) {
	env := testEnv()
	statd := env.Mappings[7] // tcp
	for _, tc := range []struct {
		args []byte
		port uint32
	}{
		{be(ProgPortmap, 2, ProtTCP, 0), 111},
		{be(ProgStatus, 1, ProtTCP, 0), uint32(statd.Port)},
		{be(ProgStatus, 9, ProtTCP, 0), uint32(statd.Port)}, // any version, like rpcbind
		{be(100003, 3, ProtTCP, 0), 0},                      // NFS is not registered
	} {
		c, err := Parse(call(ProgPortmap, 2, 3, tc.args))
		require.NoError(t, err)
		q, err := ParseQuery(c)
		require.NoError(t, err)
		require.Equal(t, "tcp", q.Netid)
		body, status := Reply(c, env)
		require.Equal(t, "SUCCESS", status)
		require.Equal(t, append(be(0x01020304, 1, 0, 0, 0, 0), be(tc.port)...), body)
	}
}

func TestReplyRPCBindV3(t *testing.T) {
	env := testEnv()
	getaddr := append(be(ProgPortmap, 3), append(xdrStr("tcp"), append(xdrStr(""), xdrStr("")...)...)...)
	c, err := Parse(call(ProgPortmap, 3, 3, getaddr))
	require.NoError(t, err)
	require.Equal(t, "RPCBPROC_GETADDR", c.Command())
	body, status := Reply(c, env)
	require.Equal(t, "SUCCESS", status)
	require.Equal(t, xdrStr("198.51.100.1.0.111"), body[24:])

	c, err = Parse(call(ProgPortmap, 4, 4))
	require.NoError(t, err)
	body, status = Reply(c, env)
	require.Equal(t, "SUCCESS", status)
	d := &decoder{b: body[24:]}
	entries := 0
	for {
		more, err := d.u32()
		require.NoError(t, err)
		if more == 0 {
			break
		}
		prog, _ := d.u32()
		vers, _ := d.u32()
		netid, err := d.str()
		require.NoError(t, err)
		uaddr, _ := d.str()
		owner, _ := d.str()
		if entries == 0 {
			require.Equal(t, []any{uint32(ProgPortmap), uint32(4), "tcp", "0.0.0.0.0.111", "superuser"}, []any{prog, vers, netid, uaddr, owner})
		}
		entries++
	}
	require.Equal(t, 8, entries)
	require.Equal(t, len(body)-24, d.off)

	c, err = Parse(call(ProgPortmap, 3, 6))
	require.NoError(t, err)
	body, status = Reply(c, env)
	require.Equal(t, "SUCCESS", status)
	require.Equal(t, be(1760205696), body[24:])
}

func TestReplyErrors(t *testing.T) {
	env := testEnv()
	for _, tc := range []struct {
		name   string
		msg    []byte
		status string
		tail   []byte
	}{
		{"null", call(ProgPortmap, 2, 0), "SUCCESS", be(0, 0, 0, 0)},
		{"set refused", call(ProgPortmap, 2, 1, be(100003, 3, ProtTCP, 2049)), "SUCCESS", be(0, 0, 0, 0, 0)},
		{"callit", call(ProgPortmap, 2, 5, be(100003, 3, 0, 0)), "PROC_UNAVAIL", be(0, 0, 0, 3)},
		{"nfs program", call(100003, 3, 0), "PROG_UNAVAIL", be(0, 0, 0, 1)},
		{"version 5", call(ProgPortmap, 5, 4), "PROG_MISMATCH", be(0, 0, 0, 2, 2, 4)},
		{"garbage args", call(ProgPortmap, 2, 3, be(1)), "GARBAGE_ARGS", be(0, 0, 0, 4)},
	} {
		c, err := Parse(tc.msg)
		require.NoError(t, err, tc.name)
		body, status := Reply(c, env)
		require.Equal(t, tc.status, status, tc.name)
		require.Equal(t, append(be(0x01020304, MsgReply), tc.tail...), body, tc.name)
	}

	bad := call(ProgPortmap, 2, 4)
	binary.BigEndian.PutUint32(bad[8:], 3)
	c, err := Parse(bad)
	require.NoError(t, err)
	body, status := Reply(c, env)
	require.Equal(t, "RPC_MISMATCH", status)
	require.Equal(t, be(0x01020304, MsgReply, 1, 0, 2, 2), body)

	c, err = Parse(be(7, MsgReply, 0, 0, 0, 0))
	require.NoError(t, err)
	require.Equal(t, "REPLY", c.Command())
	body, _ = Reply(c, env)
	require.Nil(t, body)
}

func TestParseAuthSys(t *testing.T) {
	cred := append(be(0x5f5e100), append(xdrStr("kali"), be(0, 0, 2, 0, 10)...)...)
	msg := append(be(9, MsgCall, 2, ProgPortmap, 2, 4, AuthSysFlavor, uint32(len(cred))), cred...)
	msg = append(msg, be(0, 0)...)
	c, err := Parse(msg)
	require.NoError(t, err)
	require.Equal(t, "AUTH_SYS", AuthName(c.CredFlavor))
	require.Equal(t, &AuthSys{Stamp: 0x5f5e100, MachineName: "kali", UID: 0, GID: 0, GIDs: []uint32{0, 10}}, c.AuthSys)
}

func TestParseMalformed(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		be(1),
		be(1, 7),                                // bad msg_type
		be(1, 0, 2, ProgPortmap, 2, 4, 0, 0, 0), // short call
		be(1, 0, 2, ProgPortmap, 2, 4, 0, 500, 0, 0), // cred too long
	} {
		_, err := Parse(b)
		require.ErrorIs(t, err, ErrMalformed, "%x", b)
	}
}

// APCO Sys udp/111 probe: 32-byte CALL missing the empty AUTH_NONE verifier
// (Ochi event e773c076-56e9-4cc4-ae39-8e8ac4ce6a46).
func TestParseTruncatedCallHeader(t *testing.T) {
	b := []byte{
		0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	c, err := Parse(b)
	require.ErrorIs(t, err, ErrMalformed)
	require.NotNil(t, c)
	require.True(t, c.Header)
	require.True(t, c.Cred)
	require.Equal(t, uint32(0x12345678), c.XID)
	require.Equal(t, uint32(ProgPortmap), c.Program)
	require.Equal(t, uint32(4), c.Version)
	require.Equal(t, uint32(4), c.Procedure)
	require.Equal(t, uint32(0), c.CredFlavor)
	require.Equal(t, "RPCBPROC_DUMP", c.Command())
}

func TestReadRecordFragments(t *testing.T) {
	body := shodanDump[4:]
	wire := append(be(uint32(10)), body[:10]...)
	wire = append(wire, be(0x80000000|uint32(len(body)-10))...)
	wire = append(wire, body[10:]...)
	raw, got, truncated, err := ReadRecord(bytes.NewReader(wire), 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, wire, raw)
	require.Equal(t, body, got)

	many := bytes.Repeat(be(0), MaxFragments) // empty non-last fragments
	_, _, _, err = ReadRecord(bytes.NewReader(many), 1024)
	require.ErrorIs(t, err, ErrTooManyFragments)
}

func TestReadRecordCapsAndEOF(t *testing.T) {
	// "GET " parses as a non-last fragment of 0x47455420 bytes.
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	raw, body, truncated, err := ReadRecord(bytes.NewReader(req), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.True(t, truncated)
	require.Equal(t, req, raw)
	require.Equal(t, req[4:], body)

	big := append(be(0x80000000|5000), bytes.Repeat([]byte{0x41}, 5000)...)
	raw, body, truncated, err = ReadRecord(bytes.NewReader(big), 1024)
	require.ErrorIs(t, err, ErrRecordTooLarge)
	require.True(t, truncated)
	require.Len(t, body, 1024)
	require.Len(t, raw, 1028)

	raw, _, _, err = ReadRecord(bytes.NewReader(nil), 1024)
	require.ErrorIs(t, err, io.EOF)
	require.Empty(t, raw)

	raw, _, _, err = ReadRecord(bytes.NewReader([]byte{0x80, 0}), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, []byte{0x80, 0}, raw)
}
