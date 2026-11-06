package stun

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// capturedBinding is the Binding Request from 207.90.244.25 to udp/8088
// (run-1793997453-1.jsonl event #3, 2026-11-06).
var capturedBinding, _ = hex.DecodeString("000100002112a44230775570327132787171" + "6a6a")

func TestLooksLikeSTUN(t *testing.T) {
	require.True(t, LooksLikeSTUN(capturedBinding))

	bad := append([]byte{}, capturedBinding...)
	bad[4] = 0 // magic cookie
	require.False(t, LooksLikeSTUN(bad))

	require.False(t, LooksLikeSTUN(capturedBinding[:19]))
	// length field says 4 but no body
	lenMismatch := append([]byte{}, capturedBinding...)
	lenMismatch[3] = 4
	require.False(t, LooksLikeSTUN(lenMismatch))
	// top bits set (e.g. RTP/DTLS-ish first byte)
	top := append([]byte{}, capturedBinding...)
	top[0] = 0x80
	require.False(t, LooksLikeSTUN(top))
	require.False(t, LooksLikeSTUN([]byte("hello world, not a stun message")))
}

func TestParseCaptured(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	require.Equal(t, "binding-request", m.Command())
	require.Equal(t, "307755703271327871716a6a", m.TxID())
	require.Empty(t, m.Attributes)
}

func TestParseAttributes(t *testing.T) {
	sw := []byte("abc")
	body := []byte{0x80, 0x22, 0x00, 0x03}
	body = append(body, sw...)
	body = append(body, 0)                                  // padding
	body = append(body, 0x80, 0x28, 0x00, 0x04, 1, 2, 3, 4) // fingerprint
	msg := append([]byte{0x00, 0x01, 0x00, byte(len(body))}, capturedBinding[4:20]...)
	msg = append(msg, body...)

	m, err := Parse(msg)
	require.NoError(t, err)
	require.Equal(t, []string{"software", "fingerprint"}, m.Attributes)
	require.Equal(t, "abc", m.Software)
}

func TestTypeName(t *testing.T) {
	require.Equal(t, "binding-success", TypeName(0x0101))
	require.Equal(t, "binding-error", TypeName(0x0111))
	require.Equal(t, "binding-indication", TypeName(0x0011))
	require.Equal(t, "allocate-request", TypeName(0x0003))
	require.Equal(t, "refresh-success", TypeName(0x0104))
}

func TestBuildBindingSuccessIPv4(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("207.90.244.25"), Port: 25835}
	resp := BuildBindingSuccess(m, src)

	// RFC 5389 §15.2: port ^ 0x2112, address ^ 0x2112A442
	want, _ := hex.DecodeString("0101000c2112a442307755703271327871716a6a" +
		"00200008" + "0001" + "45f9" + "ee48505b")
	require.Equal(t, want, resp)
	require.True(t, LooksLikeSTUN(resp))
	r, err := Parse(resp)
	require.NoError(t, err)
	require.Equal(t, "binding-success", r.Command())
	require.Equal(t, []string{"xor-mapped-address"}, r.Attributes)
}

func TestBuildBindingSuccessIPv6(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3478}
	resp := BuildBindingSuccess(m, src)
	require.Len(t, resp, HeaderLen+4+20)
	require.Equal(t, byte(0x02), resp[HeaderLen+5])
	// un-XOR the address with cookie||txid
	key := resp[4:20]
	ip := make(net.IP, 16)
	for i := range ip {
		ip[i] = resp[HeaderLen+8+i] ^ key[i]
	}
	require.Equal(t, src.IP.String(), ip.String())
}
