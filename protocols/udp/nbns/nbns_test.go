package nbns

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/helpers/netbios"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix byte
	}{
		{"SERVER", 0x00},
		{"SERVER", 0x20},
		{"WORKGROUP", 0x00},
		{"*", 0x00},
	} {
		enc := netbios.Encode(tc.name, tc.suffix)
		got, suffix, n, ok := netbios.Decode(enc)
		require.True(t, ok, tc.name)
		require.Equal(t, tc.name, got)
		require.Equal(t, tc.suffix, suffix)
		require.Equal(t, len(enc), n)
	}
}

func TestParseShodanNBSTAT(t *testing.T) {
	raw, err := hex.DecodeString("80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")
	require.NoError(t, err)
	m, err := Parse(raw)
	require.NoError(t, err)
	require.Equal(t, uint16(0x80f0), m.TXID)
	require.True(t, m.Broadcast(), "Shodan sets the broadcast flag on a unicast query")
	require.False(t, m.Response())
	require.Equal(t, "NBSTAT", m.Command())
	require.Equal(t, "*<00>", m.Path())
}

func TestBuildNodeStatusTable(t *testing.T) {
	qname := netbios.Encode("*", 0x00)
	mac := [6]byte{0x02, 0x00, 0x01, 0x02, 0x03, 0x04}
	resp := BuildNodeStatus(0x80f0, qname, []NodeName{
		{Name: "SERVER", Suffix: 0x00},
		{Name: "SERVER", Suffix: 0x20},
		{Name: "WORKGROUP", Suffix: 0x00, Group: true},
	}, mac)
	// header + echoed question + pointer, type, class, ttl, rdlength, then the count
	countAt := 12 + len(qname) + 4 + 2 + 2 + 2 + 4 + 2
	require.Equal(t, byte(3), resp[countAt])
	base := countAt + 1
	require.Equal(t, []byte("SERVER"), trim(resp[base:base+15]))
	require.Equal(t, byte(0x00), resp[base+15])
	require.Equal(t, []byte{0x04, 0x00}, resp[base+16:base+18])
	require.Equal(t, byte(0x20), resp[base+18+15])
	require.Equal(t, []byte("WORKGROUP"), trim(resp[base+36:base+36+15]))
	require.Equal(t, []byte{0x84, 0x00}, resp[base+36+16:base+36+18])
	require.Equal(t, mac[:], resp[base+54:base+60])
}

func TestBuildNameQuery(t *testing.T) {
	qname := netbios.Encode("SERVER", 0x00)
	resp := BuildNameQuery(0x1234, qname, net.ParseIP("1.2.3.4"))
	require.Equal(t, []byte{0x12, 0x34}, resp[0:2])
	require.Equal(t, []byte{0x84, 0x00}, resp[2:4])
	require.Equal(t, []byte{1, 2, 3, 4}, resp[len(resp)-4:])
}

func trim(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == ' ' {
		i--
	}
	return b[:i]
}
