package pcom

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured on tcp/20256 (Ochi event e5e87010-e004-4784-977d-5b6afc6fddd8):
// an ASCII ID query, then a pipelined burst of two ASCII requests and one
// binary request.
const (
	capturedID     = "534965000800" + "2f3430494446310d"
	capturedBinary = "574966001b00" +
		"2f5f4f504c43" + "00fe01010000" + "0c" + "000000000000000000" + "38fd" + "0000" + "5c"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	var clean []byte
	for _, c := range []byte(s) {
		if c != ' ' {
			clean = append(clean, c)
		}
	}
	b, err := hex.DecodeString(string(clean))
	require.NoError(t, err)
	return b
}

func TestReadFrameCaptured(t *testing.T) {
	raw := mustHex(t, capturedID)
	h, msg, got, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, raw, got)
	require.Equal(t, Header{TID: 0x4953, Mode: ModeASCII, Length: 8}, h)
	require.Equal(t, []byte("/40IDF1\r"), msg)
}

func TestParseASCIICaptured(t *testing.T) {
	req, ok := ParseASCII([]byte("/40IDF1\r"))
	require.True(t, ok)
	require.Equal(t, ASCIIRequest{Unit: "40", Command: "ID", ChecksumOK: true}, req)

	req, ok = ParseASCII([]byte("/40UG 0\r"))
	require.True(t, ok)
	require.Equal(t, "UG", req.Command)
	require.False(t, req.ChecksumOK)

	req, ok = ParseASCII([]byte("/40RNJ00090178\r"))
	require.True(t, ok)
	require.Equal(t, ASCIIRequest{Unit: "40", Command: "RN", Data: "J000901", ChecksumOK: true}, req)
}

func TestParseASCIIMalformed(t *testing.T) {
	for _, in := range []string{"", "/", "/40ID", "40IDF1\r", "/40\r"} {
		_, ok := ParseASCII([]byte(in))
		require.False(t, ok, "%q", in)
	}
}

func TestParseBinaryCaptured(t *testing.T) {
	raw := mustHex(t, capturedBinary)
	h, msg, _, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, Header{TID: 0x4957, Mode: ModeBinary, Length: 27}, h)
	req, ok := ParseBinary(msg)
	require.True(t, ok)
	require.Equal(t, byte(0x00), req.Unit)
	require.Equal(t, byte(0x0c), req.Command)
	require.Empty(t, req.Data)
	require.True(t, req.HeaderOK)
}

func TestBinaryReplyRoundTrip(t *testing.T) {
	msg := mustHex(t, capturedBinary)[HeaderLen:]
	reply := BinaryReply(msg)
	require.Equal(t, msg, reply, "an empty-data request is echoed byte for byte")
	req, ok := ParseBinary(reply)
	require.True(t, ok)
	require.True(t, req.HeaderOK)
}

func TestParseBinaryRejectsShortAndOverlong(t *testing.T) {
	msg := mustHex(t, capturedBinary)[HeaderLen:]
	_, ok := ParseBinary(msg[:20])
	require.False(t, ok)
	bad := append([]byte(nil), msg...)
	bad[20] = 0xff // data length beyond the message
	_, ok = ParseBinary(bad)
	require.False(t, ok)
	_, ok = ParseBinary([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.False(t, ok)
}

func TestASCIIChecksum(t *testing.T) {
	require.Equal(t, "F1", ASCIIChecksum("40ID"))
	require.Equal(t, "78", ASCIIChecksum("40RNJ000901"))
}

func TestIDReplyIsParseable(t *testing.T) {
	id := Identity{ModelCode: "070500", Hardware: 'B', OSMajor: 3, OSMinor: 1, OSBuild: 12}
	reply := IDReply("40", id)
	require.Equal(t, byte('/'), reply[0])
	require.Equal(t, byte('\r'), reply[len(reply)-1])
	require.Contains(t, string(reply), "/A40ID070500B030112")
	req, ok := ParseASCII(reply)
	require.True(t, ok)
	require.Equal(t, "A4", req.Unit, "reply kind occupies the first body byte")
	require.True(t, req.ChecksumOK)
}

func TestErrorReply(t *testing.T) {
	reply := ErrorReply("40", ErrCodeUnrecognized)
	require.Equal(t, "/E4001"+ASCIIChecksum("E4001")+"\r", string(reply))
}

func TestBuildAndReadRoundTrip(t *testing.T) {
	frame := Build(Header{TID: 0x1234, Mode: ModeASCII}, []byte("/40IDF1\r"))
	h, msg, raw, err := ReadFrame(bytes.NewReader(frame))
	require.NoError(t, err)
	require.Equal(t, frame, raw)
	require.Equal(t, Header{TID: 0x1234, Mode: ModeASCII, Length: 8}, h)
	require.Equal(t, []byte("/40IDF1\r"), msg)
}

func TestReadFrameErrors(t *testing.T) {
	_, _, _, err := ReadFrame(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")))
	require.ErrorIs(t, err, ErrBadMode)

	_, _, _, err = ReadFrame(bytes.NewReader([]byte{1, 2, 0x65, 0, 0, 0}))
	require.ErrorIs(t, err, ErrBadLen)

	_, _, _, err = ReadFrame(bytes.NewReader([]byte{1, 2, 0x65, 0, 0xff, 0xff}))
	require.ErrorIs(t, err, ErrTooLarge)

	_, _, raw, err := ReadFrame(bytes.NewReader([]byte{1, 2, 0x65, 0, 8, 0, '/', '4'}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Len(t, raw, 8)

	_, _, raw, err = ReadFrame(bytes.NewReader([]byte{1, 2}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Len(t, raw, 2)
}
