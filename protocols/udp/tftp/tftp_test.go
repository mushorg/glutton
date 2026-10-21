package tftp

import (
	"strconv"
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

func TestNegotiate(t *testing.T) {
	size := SizeFor("f")
	require.Equal(t, SizeFor("f"), size, "stable per filename")
	require.NotEqual(t, SizeFor("f"), SizeFor("g"))

	got := Negotiate("f", []Option{
		{Name: "TSIZE", Value: "0"},
		{Name: "blksize", Value: "99999"},
		{Name: "timeout", Value: "3"},
		{Name: "windowsize", Value: "4"},
		{Name: "blksize", Value: "16"}, // duplicate
	})
	require.Equal(t, []Option{
		{Name: "tsize", Value: strconv.Itoa(size)},
		{Name: "blksize", Value: "1468"},
		{Name: "timeout", Value: "3"},
	}, got)

	for name, in := range map[string][]Option{
		"tsize on a read of a sized file": {{Name: "tsize", Value: "512"}},
		"blksize too small":               {{Name: "blksize", Value: "4"}},
		"blksize not a number":            {{Name: "blksize", Value: "big"}},
		"timeout zero":                    {{Name: "timeout", Value: "0"}},
		"timeout too large":               {{Name: "timeout", Value: "256"}},
		"unknown":                         {{Name: "foo", Value: "1"}},
	} {
		require.Empty(t, Negotiate("f", in), name)
	}
}

func TestOACKFittingNeverExceedsMax(t *testing.T) {
	opts := []Option{{Name: "tsize", Value: "123456"}, {Name: "blksize", Value: "16"}}
	full := OACKPacket(opts)
	require.Equal(t, []byte("\x00\x06tsize\x00123456\x00blksize\x0016\x00"), full)

	pkt, acked := OACKFitting(opts, len(full))
	require.Equal(t, full, pkt)
	require.Equal(t, opts, acked)

	// One byte short: the trailing option is dropped, not truncated mid-field.
	pkt, acked = OACKFitting(opts, len(full)-1)
	require.Equal(t, []byte("\x00\x06tsize\x00123456\x00"), pkt)
	require.Equal(t, opts[:1], acked)

	for max := 0; max <= len(full); max++ {
		if pkt, _ := OACKFitting(opts, max); pkt != nil {
			require.LessOrEqual(t, len(pkt), max)
		}
	}
	pkt, acked = OACKFitting(opts, 5)
	require.Nil(t, pkt)
	require.Nil(t, acked)
}
