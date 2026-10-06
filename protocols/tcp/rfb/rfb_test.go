package rfb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Version
		ok   bool
	}{
		{"RFB 003.003\n", Version33, true},
		{"RFB 003.005\n", Version33, true}, // unknown minor falls back to 3.3
		{"RFB 003.007\n", Version37, true},
		{"RFB 003.008\n", Version38, true},
		{"RFB 003.889\n", Version38, true}, // Apple Remote Desktop
		{"RFB 004.001\n", Version38, true},
		{"RFB 3.8\n", Version33, false},
		{"GET / HTTP/1", Version33, false},
		{"RFB 00a.008\n", Version33, false},
		{"RFB 003.008\r", Version33, false},
	} {
		got, ok := ParseVersion([]byte(tc.in))
		require.Equal(t, tc.ok, ok, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
}

func TestSecurityMessages(t *testing.T) {
	require.Equal(t, []byte{2, 2, 1}, SecurityTypes(SecurityVNCAuth, SecurityNone))
	require.Equal(t, []byte{0, 0, 0, 2}, SecurityType33(SecurityVNCAuth))
	require.Equal(t, []byte{0, 0, 0, 0}, SecurityResult(true, Version38, ""))
	require.Equal(t, []byte{0, 0, 0, 1}, SecurityResult(false, Version37, "nope"))
	require.Equal(t, []byte{0, 0, 0, 1, 0, 0, 0, 4, 'n', 'o', 'p', 'e'}, SecurityResult(false, Version38, "nope"))
	require.Equal(t, "VNCAuthentication", SecurityTypeName(2))
	require.Equal(t, "0x63", SecurityTypeName(99))
}

func TestServerInit(t *testing.T) {
	got := ServerInit(1024, 768, DefaultPixelFormat, "vnc")
	want := []byte{
		0x04, 0x00, 0x03, 0x00, // 1024x768
		32, 24, 0, 1, // bpp, depth, big-endian, true-colour
		0x00, 0xff, 0x00, 0xff, 0x00, 0xff, // max
		16, 8, 0, // shift
		0, 0, 0, // padding
		0, 0, 0, 3, 'v', 'n', 'c',
	}
	require.Equal(t, want, got)
}

func TestClientMessages(t *testing.T) {
	n, ok := ClientHeaderLen(MsgSetEncodings)
	require.True(t, ok)
	require.Equal(t, 3, n)
	_, ok = ClientHeaderLen(1)
	require.False(t, ok)
	require.Equal(t, "", ClientMessageName(1))
	require.Equal(t, "PointerEvent", ClientMessageName(MsgPointerEvent))

	require.Equal(t, uint64(8), ClientBodyLen(MsgSetEncodings, []byte{0, 0, 2}))
	require.Equal(t, uint64(0x01020304), ClientBodyLen(MsgClientCutText, []byte{0, 0, 0, 1, 2, 3, 4}))
	require.Equal(t, uint64(0), ClientBodyLen(MsgKeyEvent, []byte{1, 0, 0, 0, 0, 0, 0x61}))

	require.Equal(t, []int32{0, -239}, Encodings([]byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0x11}))

	down, sym := KeyEvent([]byte{1, 0, 0, 0, 0, 0xff, 0x0d})
	require.True(t, down)
	require.Equal(t, "0xff0d", KeysymName(sym))
	require.Equal(t, "a", KeysymName(0x61))
}
