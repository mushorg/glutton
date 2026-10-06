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

func TestParsePixelFormat(t *testing.T) {
	header := append([]byte{0, 0, 0}, DefaultPixelFormat.Bytes()...)
	pf, ok := ParsePixelFormat(header)
	require.True(t, ok)
	require.Equal(t, DefaultPixelFormat, pf)

	header[3] = 24 // not a valid bpp
	_, ok = ParsePixelFormat(header)
	require.False(t, ok)
	_, ok = ParsePixelFormat(header[:10])
	require.False(t, ok)
}

func TestPixel(t *testing.T) {
	c := Colour{R: 0x11, G: 0x22, B: 0x33}
	require.Equal(t, []byte{0x33, 0x22, 0x11, 0}, DefaultPixelFormat.Pixel(c))

	be := DefaultPixelFormat
	be.BigEndian = true
	require.Equal(t, []byte{0, 0x11, 0x22, 0x33}, be.Pixel(c))

	// RGB565 big-endian: 0xff,0xff,0xff -> 0xffff; red only -> 0xf800
	rgb565 := PixelFormat{BPP: 16, Depth: 16, BigEndian: true, TrueColour: true, RedMax: 31, GreenMax: 63, BlueMax: 31, RedShift: 11, GreenShift: 5}
	require.Equal(t, []byte{0xff, 0xff}, rgb565.Pixel(Colour{R: 255, G: 255, B: 255}))
	require.Equal(t, []byte{0xf8, 0x00}, rgb565.Pixel(Colour{R: 255}))

	cmap := PixelFormat{BPP: 8, Depth: 8}
	require.Equal(t, []byte{0xff}, cmap.Pixel(Colour{R: 255, G: 255, B: 255}))
}

var testScene = Scene{
	Width: 4, Height: 3,
	Background: Colour{B: 1},
	Fills: []Fill{
		{X: 1, Y: 1, Width: 2, Height: 1, Colour: Colour{B: 2}},
		{X: 3, Y: 2, Width: 5, Height: 5, Colour: Colour{B: 3}}, // clipped to 1x1
	},
}

func TestRenderRawAndRawRect(t *testing.T) {
	pf := PixelFormat{BPP: 8, TrueColour: true, BlueMax: 255}
	fb := RenderRaw(testScene, pf)
	require.Equal(t, []byte{
		1, 1, 1, 1,
		1, 2, 2, 1,
		1, 1, 1, 3,
	}, fb)
	require.Len(t, RenderRaw(testScene, DefaultPixelFormat), 4*3*4)

	full := RawRect(fb, pf, 4, 0, 0, 4, 3)
	require.Equal(t, fb, full)
	require.Same(t, &fb[0], &full[0]) // no copy for the full frame
	require.Equal(t, []byte{2, 2, 1, 1}, RawRect(fb, pf, 4, 1, 1, 2, 2))
}

func TestRRE(t *testing.T) {
	pf := PixelFormat{BPP: 8, TrueColour: true, BlueMax: 255}
	require.Equal(t, []byte{
		0, 0, 0, 2, // subrects
		1,                         // background
		2, 0, 1, 0, 1, 0, 2, 0, 1, // fill 1 at (1,1) 2x1
		3, 0, 3, 0, 2, 0, 1, 0, 1, // fill 2 clipped to (3,2) 1x1
	}, RRE(testScene, pf, 0, 0, 4, 3))
	// only the part of fill 1 inside the rect, relative to it
	require.Equal(t, []byte{0, 0, 0, 1, 1, 2, 0, 0, 0, 0, 0, 1, 0, 1}, RRE(testScene, pf, 2, 1, 1, 1))
}

func TestClampRect(t *testing.T) {
	x, y, w, h, ok := ClampRect(1000, 700, 100, 100, 1024, 768)
	require.True(t, ok)
	require.Equal(t, []uint16{1000, 700, 24, 68}, []uint16{x, y, w, h})
	_, _, _, _, ok = ClampRect(1024, 0, 10, 10, 1024, 768)
	require.False(t, ok)
	_, _, _, _, ok = ClampRect(0, 0, 0, 10, 1024, 768)
	require.False(t, ok)
}

func TestUpdateMessages(t *testing.T) {
	req, ok := ParseUpdateRequest([]byte{0, 0, 0, 0, 0, 4, 0, 3, 0})
	require.True(t, ok)
	require.Equal(t, UpdateRequest{Width: 1024, Height: 768}, req)
	req, _ = ParseUpdateRequest([]byte{1, 0, 1, 0, 2, 0, 3, 0, 4})
	require.Equal(t, UpdateRequest{Incremental: true, X: 1, Y: 2, Width: 3, Height: 4}, req)

	require.Equal(t, EncodingRaw, ChooseEncoding(nil))
	require.Equal(t, EncodingRaw, ChooseEncoding([]int32{0, -223}))
	require.Equal(t, EncodingRRE, ChooseEncoding([]int32{16, 2, 0}))
	require.Equal(t, EncodingRaw, ChooseEncoding([]int32{7, 5}))

	require.Equal(t, []byte{0, 0, 0, 0}, FramebufferUpdate())
	require.Equal(t, []byte{
		0, 0, 0, 1, // type, padding, 1 rect
		0, 1, 0, 2, 0, 1, 0, 1, // x, y, w, h
		0xff, 0xff, 0xff, 0xfe, // encoding -2
		9,
	}, FramebufferUpdate(Rect{X: 1, Y: 2, Width: 1, Height: 1, Encoding: -2, Data: []byte{9}}))
}
