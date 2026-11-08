package stun

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
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

// capturedBindingSuccess is the reply to capturedBinding from 207.90.244.25:25835,
// computed independently of BuildBindingSuccess.
const capturedBindingSuccess = "010100382112a442307755703271327871716a6a" +
	"00200008" + "0001" + "45f9" + "ee48505b" + // XOR-MAPPED-ADDRESS (§15.2)
	"00010008" + "0001" + "64eb" + "cf5af419" + // MAPPED-ADDRESS
	"80220014" + "436f7475726e2d342e362e322027476f72737427" + // SOFTWARE "Coturn-4.6.2 'Gorst'"
	"80280004" + "a29a2bb6" // FINGERPRINT

func TestBuildBindingSuccessIPv4(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("207.90.244.25"), Port: 25835}
	resp := BuildBindingSuccess(m, src)

	want, _ := hex.DecodeString(capturedBindingSuccess)
	require.Equal(t, want, resp)
	require.True(t, LooksLikeSTUN(resp))
	r, err := Parse(resp)
	require.NoError(t, err)
	require.Equal(t, "binding-success", r.Command())
	require.Equal(t, []string{"xor-mapped-address", "mapped-address", "software", "fingerprint"}, r.Attributes)
	require.Equal(t, Software, r.Software)
}

func TestBuildBindingSuccessFingerprint(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	resp := BuildBindingSuccess(m, &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 1})
	// RFC 5389 §15.5: CRC-32 of everything before the attribute, XOR 0x5354554e
	n := len(resp) - 8
	require.Equal(t, []byte{0x80, 0x28, 0x00, 0x04}, resp[n:n+4])
	require.Equal(t, crc32.ChecksumIEEE(resp[:n])^0x5354554e, binary.BigEndian.Uint32(resp[n+4:]))
}

func TestBuildBindingSuccessSoftwarePadding(t *testing.T) {
	prev := Software
	t.Cleanup(func() { Software = prev })
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 1}

	Software = "abc" // padded to 4 bytes
	r, err := Parse(BuildBindingSuccess(m, src))
	require.NoError(t, err)
	require.Equal(t, "abc", r.Software)
	require.Equal(t, []string{"xor-mapped-address", "mapped-address", "software", "fingerprint"}, r.Attributes)

	Software = ""
	r, err = Parse(BuildBindingSuccess(m, src))
	require.NoError(t, err)
	require.Equal(t, []string{"xor-mapped-address", "mapped-address", "fingerprint"}, r.Attributes)
}

func TestBuildBindingSuccessIPv6(t *testing.T) {
	m, err := Parse(capturedBinding)
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3478}
	resp := BuildBindingSuccess(m, src)
	require.True(t, LooksLikeSTUN(resp))
	require.Equal(t, byte(0x02), resp[HeaderLen+5])
	// un-XOR the address with cookie||txid
	key := resp[4:20]
	ip := make(net.IP, 16)
	for i := range ip {
		ip[i] = resp[HeaderLen+8+i] ^ key[i]
	}
	require.Equal(t, src.IP.String(), ip.String())
}
