package acpp

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured: Ochi event 94df0a05-65ab-4ef9-900d-9f3be446bbaf (tcp/5009, Shodan).
var shodanProbe = append([]byte("acpp"), make([]byte, HeaderSize-4)...)

func request(cmd uint32, bodySize int32) []byte {
	raw := make([]byte, HeaderSize)
	copy(raw, Magic)
	binary.BigEndian.PutUint32(raw[4:], Version)
	binary.BigEndian.PutUint32(raw[16:], uint32(bodySize))
	binary.BigEndian.PutUint32(raw[28:], cmd)
	binary.BigEndian.PutUint32(raw[8:], Checksum(raw))
	return raw
}

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader(shodanProbe)
	require.NoError(t, err)
	require.Equal(t, Header{}, h)

	_, err = ParseHeader([]byte("acpp"))
	require.ErrorIs(t, err, ErrNotACPP)
	_, err = ParseHeader(make([]byte, HeaderSize))
	require.ErrorIs(t, err, ErrNotACPP)

	raw := request(0x14, 24)
	raw[48] = 0x5a
	h, err = ParseHeader(raw)
	require.NoError(t, err)
	require.Equal(t, uint32(Version), h.Version)
	require.Equal(t, uint32(0x14), h.Command)
	require.Equal(t, int32(24), h.BodySize)
	require.Equal(t, byte(0x5a), h.Key[0])
}

func TestValidate(t *testing.T) {
	h, _ := ParseHeader(shodanProbe)
	require.Equal(t, ErrVersion, Validate(h, shodanProbe))

	bad := request(0x14, -1)
	bad[8] ^= 0xff
	h, _ = ParseHeader(bad)
	require.Equal(t, ErrChecksum, Validate(h, bad))

	unknown := request(0x99, -1)
	h, _ = ParseHeader(unknown)
	require.Equal(t, ErrUnsupported, Validate(h, unknown))

	ok := request(0x1a, -1)
	h, _ = ParseHeader(ok)
	require.Equal(t, int32(0), Validate(h, ok))
}

func TestBuildReply(t *testing.T) {
	// Golden values computed independently with Python's zlib.adler32 and
	// struct.pack("!4s8i12x32s48x", ...).
	reply := BuildReply(0, ErrVersion)
	require.Len(t, reply, HeaderSize)
	require.Equal(t, "61637070000300012c4e05520000000100000000000000000000000000000000ffffe5c5", hex.EncodeToString(reply[:36]))
	require.Equal(t, make([]byte, HeaderSize-36), reply[36:])

	reply = BuildReply(0x14, ErrAuthentication)
	require.Equal(t, "616370700003000125b7053f0000000100000000000000000000000000000014ffffe59e", hex.EncodeToString(reply[:36]))

	h, err := ParseHeader(reply)
	require.NoError(t, err)
	require.Equal(t, Checksum(reply), h.HeaderChecksum)
	require.Equal(t, ErrAuthentication, h.ErrorCode)
	require.Equal(t, uint32(1), h.BodyChecksum)
}

func TestCommandName(t *testing.T) {
	require.Equal(t, "getprop", CommandName(0x14))
	require.Equal(t, "auth", CommandName(0x1a))
	require.Equal(t, "unknown", CommandName(0))
}
