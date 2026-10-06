// Package rfb parses client messages and builds server messages for the
// RFB (VNC) protocol, versions 3.3, 3.7 and 3.8 (RFC 6143).
package rfb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

// Version is the negotiated protocol version.
type Version int

const (
	Version33 Version = iota
	Version37
	Version38
)

func (v Version) String() string {
	switch v {
	case Version37:
		return "3.7"
	case Version38:
		return "3.8"
	}
	return "3.3"
}

// VersionLen is the length of a ProtocolVersion message ("RFB 003.008\n").
const VersionLen = 12

// ServerVersion is the ProtocolVersion the honeypot announces.
var ServerVersion = []byte("RFB 003.008\n")

// ParseVersion parses a client ProtocolVersion. Unknown minor versions map to
// 3.3 and anything newer than 3.8 maps to 3.8, as RFC 6143 §7.1.1 requires.
func ParseVersion(data []byte) (Version, bool) {
	if len(data) != VersionLen || !bytes.HasPrefix(data, []byte("RFB ")) || data[7] != '.' || data[11] != '\n' {
		return Version33, false
	}
	major, err := strconv.Atoi(string(data[4:7]))
	if err != nil {
		return Version33, false
	}
	minor, err := strconv.Atoi(string(data[8:11]))
	if err != nil {
		return Version33, false
	}
	switch {
	case major > 3 || (major == 3 && minor >= 8):
		return Version38, true
	case major == 3 && minor == 7:
		return Version37, true
	}
	return Version33, true
}

// Security types.
const (
	SecurityInvalid uint8 = 0
	SecurityNone    uint8 = 1
	SecurityVNCAuth uint8 = 2
)

// SecurityTypeName names a security type for decoded events.
func SecurityTypeName(t uint8) string {
	switch t {
	case SecurityInvalid:
		return "Invalid"
	case SecurityNone:
		return "None"
	case SecurityVNCAuth:
		return "VNCAuthentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 30:
		return "AppleARD"
	}
	return fmt.Sprintf("0x%02x", t)
}

// SecurityTypes builds the 3.7+ security handshake: a count byte followed by
// the offered types.
func SecurityTypes(types ...uint8) []byte {
	return append([]byte{uint8(len(types))}, types...)
}

// SecurityType33 builds the 3.3 handshake, where the server picks the type.
func SecurityType33(t uint8) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(t))
}

// ChallengeLen is the size of the VNC authentication challenge and response.
const ChallengeLen = 16

// SecurityResult builds a SecurityResult. The failure reason is only sent
// to 3.8 clients; earlier versions do not expect one.
func SecurityResult(ok bool, v Version, reason string) []byte {
	if ok {
		return []byte{0, 0, 0, 0}
	}
	out := []byte{0, 0, 0, 1}
	if v == Version38 {
		out = binary.BigEndian.AppendUint32(out, uint32(len(reason)))
		out = append(out, reason...)
	}
	return out
}

// PixelFormat is the 16-byte PIXEL_FORMAT structure.
type PixelFormat struct {
	BPP, Depth                      uint8
	BigEndian, TrueColour           bool
	RedMax, GreenMax, BlueMax       uint16
	RedShift, GreenShift, BlueShift uint8
}

// DefaultPixelFormat is 32bpp little-endian true colour, which is what most
// VNC servers advertise.
var DefaultPixelFormat = PixelFormat{
	BPP: 32, Depth: 24, TrueColour: true,
	RedMax: 255, GreenMax: 255, BlueMax: 255,
	RedShift: 16, GreenShift: 8, BlueShift: 0,
}

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// Bytes encodes the pixel format, including its 3 padding bytes.
func (p PixelFormat) Bytes() []byte {
	out := []byte{p.BPP, p.Depth, boolByte(p.BigEndian), boolByte(p.TrueColour)}
	out = binary.BigEndian.AppendUint16(out, p.RedMax)
	out = binary.BigEndian.AppendUint16(out, p.GreenMax)
	out = binary.BigEndian.AppendUint16(out, p.BlueMax)
	return append(out, p.RedShift, p.GreenShift, p.BlueShift, 0, 0, 0)
}

// ServerInit builds the ServerInit message.
func ServerInit(width, height uint16, pf PixelFormat, name string) []byte {
	out := binary.BigEndian.AppendUint16(nil, width)
	out = binary.BigEndian.AppendUint16(out, height)
	out = append(out, pf.Bytes()...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(name)))
	return append(out, name...)
}

// Client-to-server message types.
const (
	MsgSetPixelFormat           uint8 = 0
	MsgSetEncodings             uint8 = 2
	MsgFramebufferUpdateRequest uint8 = 3
	MsgKeyEvent                 uint8 = 4
	MsgPointerEvent             uint8 = 5
	MsgClientCutText            uint8 = 6
)

// clientHeaderLen is the fixed size of each client message after its type
// byte; variable-length bodies follow it.
var clientHeaderLen = map[uint8]int{
	MsgSetPixelFormat:           19,
	MsgSetEncodings:             3,
	MsgFramebufferUpdateRequest: 9,
	MsgKeyEvent:                 7,
	MsgPointerEvent:             5,
	MsgClientCutText:            7,
}

var clientMessageNames = map[uint8]string{
	MsgSetPixelFormat:           "SetPixelFormat",
	MsgSetEncodings:             "SetEncodings",
	MsgFramebufferUpdateRequest: "FramebufferUpdateRequest",
	MsgKeyEvent:                 "KeyEvent",
	MsgPointerEvent:             "PointerEvent",
	MsgClientCutText:            "ClientCutText",
}

// ClientMessageName names a client message type, or returns "" if unknown.
func ClientMessageName(t uint8) string {
	return clientMessageNames[t]
}

// ClientHeaderLen returns the fixed header size following the type byte.
func ClientHeaderLen(t uint8) (int, bool) {
	n, ok := clientHeaderLen[t]
	return n, ok
}

// ClientBodyLen returns the variable body size announced in a message header
// (the bytes after the type byte). Fixed-size messages have no body.
func ClientBodyLen(t uint8, header []byte) uint64 {
	switch t {
	case MsgSetEncodings:
		if len(header) >= 3 {
			return uint64(binary.BigEndian.Uint16(header[1:3])) * 4
		}
	case MsgClientCutText:
		if len(header) >= 7 {
			return uint64(binary.BigEndian.Uint32(header[3:7]))
		}
	}
	return 0
}

// Encodings decodes the encoding list of a SetEncodings body.
func Encodings(body []byte) []int32 {
	out := make([]int32, 0, len(body)/4)
	for i := 0; i+4 <= len(body); i += 4 {
		out = append(out, int32(binary.BigEndian.Uint32(body[i:i+4])))
	}
	return out
}

// KeyEvent decodes a KeyEvent header into its down flag and keysym.
func KeyEvent(header []byte) (bool, uint32) {
	if len(header) < 7 {
		return false, 0
	}
	return header[0] != 0, binary.BigEndian.Uint32(header[3:7])
}

// KeysymName renders a keysym as its Latin-1 character when printable, or as
// hex otherwise (e.g. 0xff0d for Return).
func KeysymName(sym uint32) string {
	if (sym >= 0x20 && sym <= 0x7e) || (sym >= 0xa0 && sym <= 0xff) {
		return string(rune(sym))
	}
	return fmt.Sprintf("0x%04x", sym)
}

// ParsePixelFormat decodes a SetPixelFormat header (3 padding bytes followed
// by PIXEL_FORMAT). Only 8, 16 and 32 bpp are valid per RFC 6143 §7.4.
func ParsePixelFormat(header []byte) (PixelFormat, bool) {
	if len(header) < 19 {
		return PixelFormat{}, false
	}
	b := header[3:]
	pf := PixelFormat{
		BPP: b[0], Depth: b[1], BigEndian: b[2] != 0, TrueColour: b[3] != 0,
		RedMax:   binary.BigEndian.Uint16(b[4:6]),
		GreenMax: binary.BigEndian.Uint16(b[6:8]),
		BlueMax:  binary.BigEndian.Uint16(b[8:10]),
		RedShift: b[10], GreenShift: b[11], BlueShift: b[12],
	}
	switch pf.BPP {
	case 8, 16, 32:
		return pf, true
	}
	return PixelFormat{}, false
}

// Colour is an 8-bit-per-channel RGB colour.
type Colour struct{ R, G, B uint8 }

func scale(v uint8, max uint16) uint32 {
	return uint32(v) * uint32(max) / 255
}

// Pixel encodes a colour in the pixel format. Colour-map formats get a
// BGR233 index; the honeypot never sends SetColourMapEntries, so the colours
// are wrong but the stream stays in sync.
func (p PixelFormat) Pixel(c Colour) []byte {
	var v uint32
	if p.TrueColour {
		v = scale(c.R, p.RedMax)<<p.RedShift | scale(c.G, p.GreenMax)<<p.GreenShift | scale(c.B, p.BlueMax)<<p.BlueShift
	} else {
		v = uint32(c.B>>6)<<6 | uint32(c.G>>5)<<3 | uint32(c.R>>5)
	}
	out := make([]byte, p.BPP/8)
	switch {
	case len(out) == 1:
		out[0] = uint8(v)
	case len(out) == 2 && p.BigEndian:
		binary.BigEndian.PutUint16(out, uint16(v))
	case len(out) == 2:
		binary.LittleEndian.PutUint16(out, uint16(v))
	case p.BigEndian:
		binary.BigEndian.PutUint32(out, v)
	default:
		binary.LittleEndian.PutUint32(out, v)
	}
	return out
}

// Fill is a solid-coloured rectangle of a Scene.
type Fill struct {
	X, Y, Width, Height uint16
	Colour              Colour
}

// Scene is a static desktop: a background with solid fills painted over it in
// order.
type Scene struct {
	Width, Height uint16
	Background    Colour
	Fills         []Fill
}

// RenderRaw renders the whole scene as Raw pixel data, row by row.
func RenderRaw(s Scene, pf PixelFormat) []byte {
	bpp := int(pf.BPP / 8)
	w, h := int(s.Width), int(s.Height)
	out := make([]byte, w*h*bpp)
	paint := func(x, y, fw, fh int, c Colour) {
		px := pf.Pixel(c)
		for row := y; row < y+fh; row++ {
			for col := x; col < x+fw; col++ {
				copy(out[(row*w+col)*bpp:], px)
			}
		}
	}
	paint(0, 0, w, h, s.Background)
	for _, f := range s.Fills {
		if x, y, fw, fh, ok := ClampRect(f.X, f.Y, f.Width, f.Height, s.Width, s.Height); ok {
			paint(int(x), int(y), int(fw), int(fh), f.Colour)
		}
	}
	return out
}

// RawRect cuts the Raw data of a rectangle out of a full framebuffer rendered
// by RenderRaw. The full rectangle returns fb itself without copying.
func RawRect(fb []byte, pf PixelFormat, fbWidth, x, y, w, h uint16) []byte {
	bpp := int(pf.BPP / 8)
	if x == 0 && y == 0 && w == fbWidth && len(fb) == int(fbWidth)*int(h)*bpp {
		return fb
	}
	out := make([]byte, 0, int(w)*int(h)*bpp)
	for row := int(y); row < int(y)+int(h); row++ {
		start := (row*int(fbWidth) + int(x)) * bpp
		out = append(out, fb[start:start+int(w)*bpp]...)
	}
	return out
}

// RRE encodes the part of a scene inside a rectangle as RRE: a subrectangle
// count, the background pixel, then one pixel and relative x,y,w,h per fill.
func RRE(s Scene, pf PixelFormat, x, y, w, h uint16) []byte {
	var subs []byte
	n := 0
	for _, f := range s.Fills {
		fx, fy, fw, fh, ok := ClampRect(f.X, f.Y, f.Width, f.Height, s.Width, s.Height)
		if !ok {
			continue
		}
		// intersect with the requested rectangle
		x0, y0 := max(fx, x), max(fy, y)
		x1, y1 := min(int(fx)+int(fw), int(x)+int(w)), min(int(fy)+int(fh), int(y)+int(h))
		if int(x0) >= x1 || int(y0) >= y1 {
			continue
		}
		subs = append(subs, pf.Pixel(f.Colour)...)
		subs = binary.BigEndian.AppendUint16(subs, x0-x)
		subs = binary.BigEndian.AppendUint16(subs, y0-y)
		subs = binary.BigEndian.AppendUint16(subs, uint16(x1-int(x0)))
		subs = binary.BigEndian.AppendUint16(subs, uint16(y1-int(y0)))
		n++
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(n))
	out = append(out, pf.Pixel(s.Background)...)
	return append(out, subs...)
}

// ClampRect clips a rectangle to a width x height framebuffer. ok is false
// when nothing is left.
func ClampRect(x, y, w, h, width, height uint16) (uint16, uint16, uint16, uint16, bool) {
	if x >= width || y >= height || w == 0 || h == 0 {
		return 0, 0, 0, 0, false
	}
	w = uint16(min(int(w), int(width)-int(x)))
	h = uint16(min(int(h), int(height)-int(y)))
	return x, y, w, h, true
}

// UpdateRequest is a decoded FramebufferUpdateRequest.
type UpdateRequest struct {
	Incremental         bool
	X, Y, Width, Height uint16
}

// ParseUpdateRequest decodes a FramebufferUpdateRequest header.
func ParseUpdateRequest(header []byte) (UpdateRequest, bool) {
	if len(header) < 9 {
		return UpdateRequest{}, false
	}
	return UpdateRequest{
		Incremental: header[0] != 0,
		X:           binary.BigEndian.Uint16(header[1:3]),
		Y:           binary.BigEndian.Uint16(header[3:5]),
		Width:       binary.BigEndian.Uint16(header[5:7]),
		Height:      binary.BigEndian.Uint16(header[7:9]),
	}, true
}

// Encodings the honeypot can send.
const (
	EncodingRaw int32 = 0
	EncodingRRE int32 = 2
)

// ChooseEncoding picks the first encoding in the client's preference order
// that the honeypot supports. Raw is always allowed, even if not listed.
func ChooseEncoding(client []int32) int32 {
	for _, e := range client {
		if e == EncodingRaw || e == EncodingRRE {
			return e
		}
	}
	return EncodingRaw
}

// Rect is one rectangle of a FramebufferUpdate; Data is its encoded pixels.
type Rect struct {
	X, Y, Width, Height uint16
	Encoding            int32
	Data                []byte
}

// Header encodes the 12-byte rectangle header that precedes Data.
func (r Rect) Header() []byte {
	out := binary.BigEndian.AppendUint16(nil, r.X)
	out = binary.BigEndian.AppendUint16(out, r.Y)
	out = binary.BigEndian.AppendUint16(out, r.Width)
	out = binary.BigEndian.AppendUint16(out, r.Height)
	return binary.BigEndian.AppendUint32(out, uint32(r.Encoding))
}

// FramebufferUpdateHeader builds the 4-byte message header announcing n
// rectangles: message-type 0, padding, u16 count.
func FramebufferUpdateHeader(n int) []byte {
	return binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(n))
}

// FramebufferUpdate builds a complete FramebufferUpdate message.
func FramebufferUpdate(rects ...Rect) []byte {
	out := FramebufferUpdateHeader(len(rects))
	for _, r := range rects {
		out = append(out, r.Header()...)
		out = append(out, r.Data...)
	}
	return out
}
