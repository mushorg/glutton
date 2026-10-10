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
