package cql

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// optionsV4 is the binaryedge probe from run-1794063438-2 event #6: v4
// OPTIONS on stream 1 with an empty body.
var optionsV4 = []byte{0x04, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00}

func TestReadFrameOptions(t *testing.T) {
	raw, hdr, err := ReadFrame(bytes.NewReader(optionsV4))
	require.NoError(t, err)
	require.Equal(t, optionsV4, raw)
	require.Equal(t, &Header{Version: 4, Stream: 1, Opcode: OpOptions}, hdr)
	require.Equal(t, "OPTIONS", OpcodeName(hdr.Opcode))
}

func TestReadFrameLegacyHeader(t *testing.T) {
	in := []byte{0x02, 0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00}
	raw, hdr, err := ReadFrame(bytes.NewReader(in))
	require.NoError(t, err)
	require.Equal(t, in, raw)
	require.Equal(t, &Header{Version: 2, Stream: 5, Opcode: OpOptions}, hdr)
}

func TestReadFrameBody(t *testing.T) {
	body := StringBody("x")
	in := append([]byte{0x04, 0x00, 0x00, 0x07, OpStartup, 0x00, 0x00, 0x00, byte(len(body))}, body...)
	raw, hdr, err := ReadFrame(bytes.NewReader(append(in, 0xaa)))
	require.NoError(t, err)
	require.Equal(t, in, raw)
	require.Equal(t, uint32(len(body)), hdr.Length)
}

func TestReadFrameErrors(t *testing.T) {
	raw, hdr, err := ReadFrame(bytes.NewReader([]byte("GET / HTTP/1.0\r\n")))
	require.ErrorIs(t, err, ErrUnknownVersion)
	require.Equal(t, []byte("G"), raw)
	require.Nil(t, hdr)

	raw, hdr, err = ReadFrame(bytes.NewReader(optionsV4[:5]))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, optionsV4[:5], raw)
	require.Nil(t, hdr)

	big := []byte{0x04, 0x00, 0x00, 0x01, OpQuery, 0x7f, 0xff, 0xff, 0xff}
	raw, hdr, err = ReadFrame(bytes.NewReader(big))
	require.ErrorIs(t, err, ErrBodyTooLarge)
	require.Equal(t, big, raw)
	require.NotNil(t, hdr)

	short := []byte{0x04, 0x00, 0x00, 0x01, OpQuery, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02}
	raw, _, err = ReadFrame(bytes.NewReader(short))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, short, raw)

	_, _, err = ReadFrame(bytes.NewReader(nil))
	require.ErrorIs(t, err, io.EOF)
}

func TestBuildFrame(t *testing.T) {
	require.Equal(t, []byte{0x84, 0x00, 0x00, 0x01, OpReady, 0x00, 0x00, 0x00, 0x00}, BuildFrame(4, 1, OpReady, nil))
	require.Equal(t, []byte{0x82, 0x00, 0x05, OpReady, 0x00, 0x00, 0x00, 0x00}, BuildFrame(2, 5, OpReady, nil))
	require.Equal(t, []byte{0x83, 0x00, 0xff, 0xff, OpAuthSuccess, 0x00, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff},
		BuildFrame(3, -1, OpAuthSuccess, NullBytes()))
}

func TestStringMultimap(t *testing.T) {
	got := StringMultimap([]MultimapEntry{{Key: "K", Values: []string{"a", "bc"}}})
	require.Equal(t, []byte{0x00, 0x01, 0x00, 0x01, 'K', 0x00, 0x02, 0x00, 0x01, 'a', 0x00, 0x02, 'b', 'c'}, got)
}

func TestErrorBody(t *testing.T) {
	require.Equal(t, []byte{0x00, 0x00, 0x10, 0x02, 0x00, 0x02, 'n', 'o'}, ErrorBody(ErrIsBootstrapping, "no"))
}

func stringMap(kv ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(kv)/2))
	for _, s := range kv {
		b = append(b, StringBody(s)...)
	}
	return b
}

func TestParseStringMap(t *testing.T) {
	m, err := ParseStringMap(stringMap("CQL_VERSION", "3.0.0", "DRIVER_NAME", "x"))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"CQL_VERSION": "3.0.0", "DRIVER_NAME": "x"}, m)

	_, err = ParseStringMap([]byte{0x00, 0x02, 0x00, 0x01, 'k'})
	require.ErrorIs(t, err, ErrShortBody)
}

func TestParseStringList(t *testing.T) {
	l, err := ParseStringList(append([]byte{0x00, 0x01}, StringBody("TOPOLOGY_CHANGE")...))
	require.NoError(t, err)
	require.Equal(t, []string{"TOPOLOGY_CHANGE"}, l)
}

func TestParseLongStringAndBytes(t *testing.T) {
	q, err := ParseLongString([]byte{0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c', 0x00, 0x01})
	require.NoError(t, err)
	require.Equal(t, "abc", q)

	_, err = ParseLongString([]byte{0x00, 0x00, 0x00, 0x09, 'a'})
	require.ErrorIs(t, err, ErrShortBody)

	b, err := ParseBytes([]byte{0x00, 0x00, 0x00, 0x02, 'h', 'i'})
	require.NoError(t, err)
	require.Equal(t, []byte("hi"), b)

	b, err = ParseBytes(NullBytes())
	require.NoError(t, err)
	require.Nil(t, b)
}

func TestParsePlainSASL(t *testing.T) {
	u, p, ok := ParsePlainSASL([]byte("\x00cassandra\x00cassandra"))
	require.True(t, ok)
	require.Equal(t, "cassandra", u)
	require.Equal(t, "cassandra", p)

	_, _, ok = ParsePlainSASL([]byte("nonul"))
	require.False(t, ok)
}
