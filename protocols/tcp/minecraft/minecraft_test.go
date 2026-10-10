package minecraft

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVarIntRoundTrip(t *testing.T) {
	for _, v := range []int32{0, 1, 127, 128, 255, 25565, 2147483647, -1, -2147483648} {
		enc := AppendVarInt(nil, v)
		got, n, err := ReadVarInt(bytes.NewReader(enc))
		require.NoError(t, err)
		require.Equal(t, v, got)
		require.Equal(t, len(enc), n)
	}
	require.Equal(t, []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, AppendVarInt(nil, -1))
}

func TestVarIntTooLong(t *testing.T) {
	_, _, err := ReadVarInt(bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}))
	require.ErrorIs(t, err, ErrVarIntTooLong)
}

// Observed scanner probe with a correctly sized 15-char address.
var probeHandshake = []byte{
	0x19, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x0f,
	'1', '2', '7', '.', '0', '.', '0', '.', '1', '0', '0', '0', '0', '0', '0',
	0x63, 0xdd, 0x01,
}

func TestParseHandshake(t *testing.T) {
	pkt, err := ReadPacket(bytes.NewReader(probeHandshake))
	require.NoError(t, err)
	require.Equal(t, int32(IDHandshake), pkt.ID)
	require.Equal(t, probeHandshake, pkt.Raw)
	hs, err := ParseHandshake(pkt.Body)
	require.NoError(t, err)
	require.Equal(t, Handshake{ProtocolVersion: -1, Address: "127.0.0.1000000", Port: 25565, NextState: 1}, hs)
}

func TestReadPacketRejects(t *testing.T) {
	_, err := ReadPacket(bytes.NewReader(AppendVarInt(nil, MaxPacketLen+1)))
	require.ErrorIs(t, err, ErrPacketTooLarge)
	_, err = ReadPacket(bytes.NewReader([]byte{0x00}))
	require.ErrorIs(t, err, ErrPacketTooLarge)
}

func TestReadPacketTruncatedKeepsRaw(t *testing.T) {
	pkt, err := ReadPacket(bytes.NewReader(probeHandshake[:10]))
	require.Error(t, err)
	require.Equal(t, probeHandshake[:10], pkt.Raw)
}

func TestParseHandshakeStringOverrun(t *testing.T) {
	// string length 0x0f but only 3 bytes follow
	_, err := ParseHandshake([]byte{0x01, 0x0f, 'a', 'b', 'c'})
	require.ErrorIs(t, err, ErrBadString)
}

func TestBuildStatusResponse(t *testing.T) {
	def := BuildStatusResponse(-1)
	require.Contains(t, string(def), `"protocol":769`)
	echo := BuildStatusResponse(767)
	require.Contains(t, string(echo), `"protocol":767`)
	require.Contains(t, string(echo), `"description":{"text":"A Minecraft Server"}`)
	pkt, err := ReadPacket(bytes.NewReader(echo))
	require.NoError(t, err)
	require.Equal(t, int32(IDStatusResp), pkt.ID)
}

func TestPongAndLogin(t *testing.T) {
	ping := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	require.Equal(t, append([]byte{9, 1}, ping...), BuildPong(ping))
	_, err := ParsePing(ping[:4])
	require.ErrorIs(t, err, ErrShortBody)

	name, err := ParseLoginStart([]byte{0x03, 'b', 'o', 'b', 0xaa})
	require.NoError(t, err)
	require.Equal(t, "bob", name)
	require.Contains(t, string(BuildLoginDisconnect()), `"text"`)
}

// matscanPing is the Handshake + Status Request from Ochi event
// 840d93b6-c4c3-4981-b817-5c46a41b25e2 (tcp/49214): protocol 47, address
// "matscan", port 1337, next state 1.
var matscanPing = []byte{0x0d, 0x00, 0x2f, 0x07, 'm', 'a', 't', 's', 'c', 'a', 'n', 0x05, 0x39, 0x01, 0x01, 0x00}

func TestLooksLikeHandshake(t *testing.T) {
	classic := append([]byte{0x19, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x0f}, "mc.example.test"...)
	classic = append(classic, 0x63, 0xdd, 0x01, 0x01, 0x00)
	long := append([]byte{0x80 | 0x06, 0x02, 0x00, 0x2f, 0xff, 0x01}, bytes.Repeat([]byte("a"), 255)...)
	long = append(long, 0x63, 0xdd, 0x02)

	for name, b := range map[string][]byte{
		"matscan":        matscanPing,
		"classic":        classic,
		"handshake only": matscanPing[:14],
		"login":          {0x06, 0x00, 0x00, 0x00, 0x63, 0xdd, 0x02},
		"transfer":       {0x06, 0x00, 0x00, 0x00, 0x63, 0xdd, 0x03},
		"2-byte length":  long,
	} {
		require.True(t, LooksLikeHandshake(b), name)
		n, ok := HandshakeLen(b)
		require.True(t, ok, name)
		require.LessOrEqual(t, n, len(b), name)
	}
	require.Equal(t, 14, func() int { n, _ := HandshakeLen(matscanPing); return n }())
}

func TestLooksLikeHandshakeRejects(t *testing.T) {
	bad := func(state byte) []byte {
		b := bytes.Clone(matscanPing[:14])
		b[13] = state
		return b
	}
	for name, b := range map[string][]byte{
		"http":          []byte("GET / HTTP/1.1\r\n\r\n"),
		"socks4":        {0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00},
		"socks5":        {0x05, 0x01, 0x00},
		"rdp tpkt":      {0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00},
		"adb cnxn":      []byte("CNXN\x00\x00\x00\x01\x00\x10\x00\x00"),
		"random":        {0x61, 0x8c, 0xb0, 0xc4, 0x75, 0xfc, 0x1e, 0xcd, 0x8d, 0xf4, 0x42, 0x83},
		"truncated":     matscanPing[:10],
		"state 0":       bad(0),
		"state 4":       bad(4),
		"too short":     {0x05, 0x00, 0x00, 0x00, 0x63, 0xdd},
		"trailing body": {0x07, 0x00, 0x00, 0x00, 0x63, 0xdd, 0x01, 0x00},
		"address over":  {0x06, 0x00, 0x00, 0x09, 0x63, 0xdd, 0x01},
		"bad utf8":      {0x07, 0x00, 0x00, 0x01, 0xff, 0x63, 0xdd, 0x01},
		"mongodb":       {0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00},
		"empty":         {},
	} {
		require.False(t, LooksLikeHandshake(b), name)
	}
}
