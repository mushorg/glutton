package rip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured RIPv1 whole-table request (Ochi event d52ce31e-9b16-40a0-94fd-55bbed727932).
var capturedWholeTable = []byte{
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// v2SimpleAuthRequest is a synthetic RIPv2 whole-table request with a
// plaintext password entry.
func v2SimpleAuthRequest() []byte {
	b := []byte{1, 2, 0, 0, 0xff, 0xff, 0, 2}
	b = append(b, []byte("cisco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")...)
	return append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16)
}

func TestParseCapturedWholeTable(t *testing.T) {
	p, err := Parse(capturedWholeTable)
	require.NoError(t, err)
	require.Equal(t, uint8(CommandRequest), p.Command)
	require.Equal(t, uint8(1), p.Version)
	require.True(t, p.WholeTable())
	require.Nil(t, p.Auth)
	require.Len(t, p.Entries, 1)
	require.Equal(t, uint16(AFIUnspec), p.Entries[0].AFI)
	require.Equal(t, uint32(Infinity), p.Entries[0].Metric)
	require.True(t, LooksLikeRIP(capturedWholeTable))
}

func TestParseV2SimpleAuth(t *testing.T) {
	p, err := Parse(v2SimpleAuthRequest())
	require.NoError(t, err)
	require.NotNil(t, p.Auth)
	require.Equal(t, uint16(AuthSimple), p.Auth.Type)
	require.Equal(t, []byte("cisco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), p.Auth.Password)
	require.True(t, p.WholeTable())
	require.True(t, LooksLikeRIP(v2SimpleAuthRequest()))
}

func TestParseV2KeyedAuthTrailer(t *testing.T) {
	b := []byte{2, 2, 0, 0,
		0xff, 0xff, 0, 3, 0, 44, 7, 16, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 2, 0, 9, 10, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0xff, 0xff, 0, 1}
	b = append(b, make([]byte, 16)...)
	b[len(b)-1] = 0xaa
	p, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, &Auth{Type: AuthKeyed, PacketLen: 44, KeyID: 7, DataLen: 16, Sequence: 42, Digest: b[48:]}, p.Auth)
	require.Equal(t, []Entry{{
		AFI: AFIInet, RouteTag: 9,
		Address: net.IP{10, 0, 0, 0}, Mask: net.IP{255, 0, 0, 0}, NextHop: net.IP{0, 0, 0, 0}, Metric: 1,
	}}, p.Entries)
}

func TestParseMalformed(t *testing.T) {
	_, err := Parse([]byte{1, 1})
	require.ErrorIs(t, err, ErrShort)

	p, err := Parse(capturedWholeTable[:20])
	require.ErrorIs(t, err, ErrBadLength)
	require.Equal(t, uint8(1), p.Version)

	_, err = Parse([]byte{1, 1, 0, 0})
	require.ErrorIs(t, err, ErrNoEntries)

	_, err = Parse(append([]byte{1, 9, 0, 0}, capturedWholeTable[4:]...))
	require.ErrorIs(t, err, ErrBadVersion)

	_, err = Parse(append([]byte{1, 1, 0, 0}, make([]byte, 26*EntrySize)...))
	require.ErrorIs(t, err, ErrTooMany)
}

func TestLooksLikeRIPRejects(t *testing.T) {
	mutate := func(i int, v byte) []byte {
		b := append([]byte(nil), capturedWholeTable...)
		b[i] = v
		return b
	}
	for name, b := range map[string][]byte{
		"short":        capturedWholeTable[:20],
		"command":      mutate(0, 6),
		"version":      mutate(1, 3),
		"zero":         mutate(2, 1),
		"afi":          mutate(5, 7),
		"v1 route tag": mutate(7, 1),
		"v1 mask":      mutate(14, 1),
		"metric 0":     mutate(23, 0),
		"metric 17":    mutate(23, 17),
		"extra byte":   append(append([]byte(nil), capturedWholeTable...), 0),
		"too many":     append([]byte{1, 1, 0, 0}, make([]byte, 26*EntrySize)...),
		"dhcp-ish":     append([]byte{1, 1, 6, 0}, capturedWholeTable[4:]...),
		"empty header": {1, 1, 0, 0},
	} {
		require.False(t, LooksLikeRIP(b), name)
	}
}

func TestAnswerWholeTable(t *testing.T) {
	route := RouteFor([]byte("seed"))
	require.Equal(t, net.IP{192, 168, 70, 0}, route.Address)

	p, err := Parse(capturedWholeTable)
	require.NoError(t, err)
	resp := Answer(p, route)
	require.Equal(t, []byte{
		2, 1, 0, 0,
		0, 2, 0, 0, 192, 168, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}, resp)
	require.LessOrEqual(t, len(resp), len(capturedWholeTable))

	p, err = Parse(v2SimpleAuthRequest())
	require.NoError(t, err)
	require.Equal(t, []byte{
		2, 2, 0, 0,
		0, 2, 0, 0, 192, 168, 70, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}, Answer(p, route))
}

func TestAnswerSpecificRoutes(t *testing.T) {
	route := RouteFor([]byte("seed"))
	req := []byte{1, 2, 0, 0,
		0, 2, 0, 0, 192, 168, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
		0, 2, 0, 0, 10, 1, 2, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 16}
	p, err := Parse(req)
	require.NoError(t, err)
	require.False(t, p.WholeTable())
	require.Equal(t, []byte{2, 2, 0, 0,
		0, 2, 0, 0, 192, 168, 70, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 2, 0, 0, 10, 1, 2, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 16}, Answer(p, route))

	resp := BuildResponse(2, []Entry{route})
	rp, err := Parse(resp)
	require.NoError(t, err)
	require.Nil(t, Answer(rp, route), "responses are not answered")
}
