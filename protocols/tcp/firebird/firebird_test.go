package firebird

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// nmapConnect is the nmap Firebird probe Shodan sent to tcp/3050 in Ochi
// event e0fc5f6b-f5e3-4d4f-b68d-e2366279125c.
var nmapConnect = []byte("\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00$\x00\x00\x00\x0bservice_mgr\x00\x00\x00\x00\x02\x00\x00\x00\x13\x01\x08scanner \x04\x05nmap \x06\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\n\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04")

func opaque(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	out = append(out, b...)
	return append(out, make([]byte, (4-len(b)%4)%4)...)
}

func attachPacket(op uint32, file string, params []byte) []byte {
	b := words(op, 0)
	b = append(b, opaque([]byte(file))...)
	return append(b, opaque(params)...)
}

func read(t *testing.T, b []byte) (Packet, error) {
	t.Helper()
	return ReadPacket(bufio.NewReader(bytes.NewReader(b)), 4096)
}

func TestReadNmapConnect(t *testing.T) {
	p, err := read(t, nmapConnect)
	require.NoError(t, err)
	require.Equal(t, uint32(OpConnect), p.Op)
	require.Equal(t, nmapConnect, p.Raw)
	require.Equal(t, Connect{
		Operation:  OpAttach,
		Version:    ConnectVersion2,
		ClientArch: 36,
		File:       "service_mgr",
		OSUser:     "scanner ",
		Host:       "nmap ",
		Protocols: []Protocol{
			{Version: 8, Arch: 1, MinType: 2, MaxType: 3, Weight: 2},
			{Version: 10, Arch: 1, MinType: 2, MaxType: 3, Weight: 4},
		},
	}, p.Connect)
	require.True(t, LooksLikeConnect(nmapConnect[:ConnectPeekLen]))
}

func TestNmapConnectAccept(t *testing.T) {
	p, err := read(t, nmapConnect)
	require.NoError(t, err)
	proto, ok := SelectProtocol(p.Connect.Protocols)
	require.True(t, ok)
	require.Equal(t, []byte{0, 0, 0, 3, 0, 0, 0, 0x0a, 0, 0, 0, 1, 0, 0, 0, 3}, BuildAccept(proto))
}

func TestSelectProtocol(t *testing.T) {
	// Firebird 3 client: 10..13 with rising weight, lazy send and compression
	offer := []Protocol{
		{Version: ProtocolVersion10, Arch: ArchGeneric, MinType: 2, MaxType: 5, Weight: 2},
		{Version: ProtocolVersion11, Arch: ArchGeneric, MinType: 2, MaxType: 5, Weight: 4},
		{Version: ProtocolVersion12, Arch: ArchGeneric, MinType: 2, MaxType: 5, Weight: 6},
		{Version: protocolFlag | 13, Arch: ArchGeneric, MinType: 2, MaxType: 0x105, Weight: 8},
	}
	p, ok := SelectProtocol(offer)
	require.True(t, ok)
	require.Equal(t, uint32(ProtocolVersion12), p.Version)
	require.Equal(t, uint32(5), p.MaxType)
	require.Equal(t, uint32(12), VersionNumber(p.Version))

	// ties go to the later entry, like the server loop's >= weight
	p, ok = SelectProtocol([]Protocol{
		{Version: ProtocolVersion10, Arch: ArchGeneric, MaxType: 3, Weight: 2},
		{Version: ProtocolVersion11, Arch: ArchGeneric, MaxType: 3, Weight: 2},
	})
	require.True(t, ok)
	require.Equal(t, uint32(ProtocolVersion11), p.Version)

	// only Firebird 3+ protocols, or only native architectures
	_, ok = SelectProtocol([]Protocol{{Version: protocolFlag | 13, Arch: ArchGeneric, MaxType: 5, Weight: 8}})
	require.False(t, ok)
	_, ok = SelectProtocol([]Protocol{{Version: ProtocolVersion10, Arch: 36, MaxType: 5, Weight: 8}})
	require.False(t, ok)
	_, ok = SelectProtocol(nil)
	require.False(t, ok)
}

func TestReadServiceAttachSPB2(t *testing.T) {
	spb := append([]byte{spbVersion2, 2, tagUserName, 6}, "SYSDBA"...)
	spb = append(spb, tagPassword, 9)
	spb = append(spb, "masterkey"...)
	pkt := attachPacket(OpServiceAttach, "service_mgr", spb)
	p, err := read(t, pkt)
	require.NoError(t, err)
	require.Equal(t, uint32(OpServiceAttach), p.Op)
	require.Equal(t, pkt, p.Raw)
	require.Equal(t, Attach{File: "service_mgr", Params: Params{Username: "SYSDBA", PasswordSet: true}}, p.Attach)
}

func TestReadAttachDPB1(t *testing.T) {
	dpb := []byte{dpbVersion1, tagUserName, 6}
	dpb = append(dpb, "SYSDBA"...)
	dpb = append(dpb, tagPasswordEnc, 4, 'x', 'x', 'x', 'x')
	dpb = append(dpb, tagLCCtype, 4)
	dpb = append(dpb, "UTF8"...)
	dpb = append(dpb, tagSQLRoleName, 3)
	dpb = append(dpb, "RDB"...)
	dpb = append(dpb, tagProcessID, 4, 0x39, 0x30, 0, 0)
	dpb = append(dpb, tagProcessName, 12)
	dpb = append(dpb, "/usr/bin/isq"...)
	p, err := read(t, attachPacket(OpAttach, "/opt/firebird/employee.fdb", dpb))
	require.NoError(t, err)
	require.Equal(t, Attach{File: "/opt/firebird/employee.fdb", Params: Params{
		Username:    "SYSDBA",
		PasswordSet: true,
		Charset:     "UTF8",
		Role:        "RDB",
		ProcessID:   12345,
		ProcessName: "/usr/bin/isq",
	}}, p.Attach)
}

func TestParseWideParams(t *testing.T) {
	dpb := []byte{dpbVersion2, tagUserName, 6, 0, 0, 0}
	dpb = append(dpb, "SYSDBA"...)
	dpb = append(dpb, tagOSUser, 4, 0, 0, 0)
	dpb = append(dpb, "root"...)
	dpb = append(dpb, tagHostName, 3, 0, 0, 0)
	dpb = append(dpb, "box"...)
	require.Equal(t, Params{Username: "SYSDBA", OSUser: "root", HostName: "box"}, ParseDPB(dpb))

	spb := append([]byte{spbVersion3, tagUserName, 2, 0, 0, 0}, "me"...)
	require.Equal(t, Params{Username: "me"}, ParseSPB(spb))

	// a length past the end stops parsing without panicking
	require.Equal(t, Params{}, ParseDPB([]byte{dpbVersion1, tagUserName, 200, 'a'}))
	require.Equal(t, Params{}, ParseDPB([]byte{dpbVersion2, tagUserName, 0xff, 0xff, 0xff, 0xff}))
	require.Equal(t, Params{}, ParseDPB([]byte{9, tagUserName, 1, 'a'}))
	require.Equal(t, Params{}, ParseSPB([]byte{spbVersion2}))
}

func TestReadTruncated(t *testing.T) {
	p, err := read(t, nmapConnect[:50])
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, nmapConnect[:50], p.Raw)

	p, err = read(t, []byte{0, 0})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, []byte{0, 0}, p.Raw)
}

func TestReadCaps(t *testing.T) {
	huge := append(words(OpAttach, 0, 0xffffff00), "x"...)
	_, err := read(t, huge)
	require.ErrorIs(t, err, ErrTooLong)

	many := append(append([]byte(nil), nmapConnect[:32]...), words(maxProtocols+1)...)
	_, err = read(t, many)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestReadUnknownOpKeepsBufferedBytes(t *testing.T) {
	pkt := words(99, 1, 2)
	p, err := read(t, pkt)
	require.ErrorIs(t, err, ErrUnknownOp)
	require.Equal(t, pkt, p.Raw)
	require.Equal(t, "op_99", OpName(p.Op))
}

func TestLooksLikeConnect(t *testing.T) {
	require.False(t, LooksLikeConnect(nmapConnect[:8]))
	require.False(t, LooksLikeConnect(words(OpConnect, 99, ConnectVersion2, 36)))
	require.False(t, LooksLikeConnect(words(OpConnect, OpAttach, 7, 36)))
	require.False(t, LooksLikeConnect(words(OpConnect, OpAttach, ConnectVersion2, 0x1000)))
	require.True(t, LooksLikeConnect(words(OpConnect, OpServiceAttach, ConnectVersion3, 1)))
}

func TestBuildLoginFailed(t *testing.T) {
	want := words(OpResponse, 0, 0, 0, 0, 1, 0x14000098, 0)
	require.Equal(t, want, BuildLoginFailed())
	require.Equal(t, []byte{0, 0, 0, 4}, BuildReject())
}
