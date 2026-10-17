package tftp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var polycom = []byte("\x00\x01polycom430\x00octet\x00")

func TestParseRRQ(t *testing.T) {
	req, err := Parse(polycom)
	require.NoError(t, err)
	require.Equal(t, &Request{Opcode: OpRRQ, Filename: "polycom430", Mode: "octet"}, req)
	require.True(t, LooksLikeTFTP(polycom))
}

func TestParseWRQOptions(t *testing.T) {
	req, err := Parse([]byte("\x00\x02a.cfg\x00NetAscii\x00blksize\x001468\x00"))
	require.NoError(t, err)
	require.Equal(t, OpWRQ, req.Opcode)
	require.Equal(t, "netascii", req.Mode)
	require.Equal(t, []Option{{Name: "blksize", Value: "1468"}}, req.Options)
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"short":         []byte("\x00\x01a\x00"),
		"bad opcode":    []byte("\x00\x03a\x00octet\x00"),
		"no final nul":  []byte("\x00\x01a\x00octet"),
		"bad mode":      []byte("\x00\x01a\x00bogus\x00"),
		"empty name":    []byte("\x00\x01\x00octet\x00"),
		"odd option":    []byte("\x00\x01a\x00octet\x00blksize\x00"),
		"missing mode":  []byte("\x00\x01aaaaaaaa\x00"),
		"dns-ish bytes": {0x12, 0x34, 0x01, 0x00, 0x00, 0x01},
	} {
		require.False(t, LooksLikeTFTP(in), name)
	}
}

func TestErrorPacket(t *testing.T) {
	require.Equal(t, []byte("\x00\x05\x00\x01File not found\x00"), ErrorPacket(ErrFileNotFound, "File not found"))
}

func TestErrorFittingNeverLarger(t *testing.T) {
	for n := 5; n < 30; n++ {
		require.LessOrEqual(t, len(ErrorFitting(ErrFileNotFound, "File not found", n)), n)
	}
	require.Len(t, ErrorFitting(ErrFileNotFound, "File not found", 19), 19)
}
