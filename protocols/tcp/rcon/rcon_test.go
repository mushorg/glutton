package rcon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHeader(t *testing.T) {
	// Shodan's auth probe: size 10 although "test\0\0" follows.
	hdr, err := ParseHeader([]byte("\x0a\x00\x00\x00\x82\x02\x00\x00\x03\x00\x00\x00test\x00\x00"))
	require.NoError(t, err)
	require.Equal(t, Header{Size: 10, ID: 0x282, Type: TypeAuth}, hdr)

	_, err = ParseHeader([]byte("\x0a\x00\x00"))
	require.Error(t, err)

	_, err = ParseHeader([]byte("GET / HTTP/1.0\r\n"))
	require.ErrorIs(t, err, ErrSize)

	_, err = ParseHeader([]byte("\x09\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00"))
	require.ErrorIs(t, err, ErrSize)
}

func TestCommandName(t *testing.T) {
	require.Equal(t, "auth", CommandName(3))
	require.Equal(t, "exec", CommandName(2))
	require.Equal(t, "response", CommandName(0))
	require.Equal(t, "unknown", CommandName(7))
}

func TestBuildPacket(t *testing.T) {
	require.Equal(t,
		[]byte("\x0e\x00\x00\x00\x2a\x00\x00\x00\x03\x00\x00\x00test\x00\x00"),
		BuildPacket(42, TypeAuth, "test"))
}

func TestBuildAuthFailure(t *testing.T) {
	require.Equal(t, []byte(
		"\x0a\x00\x00\x00\x82\x02\x00\x00\x00\x00\x00\x00\x00\x00"+
			"\x0a\x00\x00\x00\xff\xff\xff\xff\x02\x00\x00\x00\x00\x00"),
		BuildAuthFailure(0x282))
}
