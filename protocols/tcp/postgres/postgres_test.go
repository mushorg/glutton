package postgres

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// sslRequest is the SSLRequest from Ochi event
// 940f5806-34a2-476f-979c-5f1d945cdc8f (tcp/5432).
var sslRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

func startup(code uint32, params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, code)
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...)
}

func reader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

func TestReadStartupSSLRequest(t *testing.T) {
	st, err := ReadStartup(reader(sslRequest), MaxStartupLen)
	require.NoError(t, err)
	require.Equal(t, Startup{Raw: sslRequest, Code: SSLRequestCode}, st)
	require.Equal(t, "SSLRequest", st.Name())
	require.Empty(t, st.Body())
}

func TestReadStartupMessage(t *testing.T) {
	msg := startup(ProtocolVersion3, "user", "postgres", "database", "template1")
	st, err := ReadStartup(reader(msg), MaxStartupLen)
	require.NoError(t, err)
	require.Equal(t, msg, st.Raw)
	require.Equal(t, "StartupMessage", st.Name())
	major, minor := st.Version()
	require.Equal(t, [2]uint16{3, 0}, [2]uint16{major, minor})

	params, err := ParseParams(st.Body())
	require.NoError(t, err)
	require.Equal(t, []Param{{"user", "postgres"}, {"database", "template1"}}, params)
}

func TestReadStartupErrors(t *testing.T) {
	st, err := ReadStartup(reader([]byte{0, 0, 0x30, 0x00, 1, 2}), MaxStartupLen)
	require.ErrorIs(t, err, ErrTooLong)
	require.Equal(t, []byte{0, 0, 0x30, 0x00}, st.Raw)

	st, err = ReadStartup(reader([]byte{0, 0, 0, 4}), MaxStartupLen)
	require.ErrorIs(t, err, ErrMalformed)
	require.Equal(t, []byte{0, 0, 0, 4}, st.Raw)

	msg := startup(ProtocolVersion3, "user", "postgres")
	st, err = ReadStartup(reader(msg[:12]), MaxStartupLen)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, msg[:12], st.Raw)

	st, err = ReadStartup(reader(sslRequest[:2]), MaxStartupLen)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, sslRequest[:2], st.Raw)
}

func TestParseParamsMalformed(t *testing.T) {
	_, err := ParseParams([]byte("user\x00postgres"))
	require.ErrorIs(t, err, ErrMalformed)
	_, err = ParseParams([]byte("user\x00postgres\x00\x00extra"))
	require.ErrorIs(t, err, ErrMalformed)
	params, err := ParseParams([]byte{0})
	require.NoError(t, err)
	require.Empty(t, params)
}

func TestReadMessage(t *testing.T) {
	pw := []byte("p\x00\x00\x00\x28md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00")
	m, err := ReadMessage(reader(pw), MaxStartupLen)
	require.NoError(t, err)
	require.Equal(t, Message{Raw: pw, Type: 'p'}, m)
	require.Equal(t, "PasswordMessage", MessageName(m.Type))
	require.Len(t, m.Body(), 36)
	require.Equal(t, "md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", m.Password())

	_, err = ReadMessage(reader([]byte{'Q', 0, 1, 0, 0}), MaxStartupLen)
	require.ErrorIs(t, err, ErrTooLong)
	_, err = ReadMessage(reader([]byte{'Q', 0, 0, 0, 3}), MaxStartupLen)
	require.ErrorIs(t, err, ErrMalformed)
	m, err = ReadMessage(reader(pw[:9]), MaxStartupLen)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, pw[:9], m.Raw)
	require.Equal(t, "type_0x7a", MessageName('z'))
}

func TestLooksLikeStartup(t *testing.T) {
	require.True(t, MayStart(sslRequest))
	require.True(t, LooksLikeStartup(sslRequest))
	require.True(t, LooksLikeStartup([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30}))
	require.True(t, LooksLikeStartup(startup(ProtocolVersion3, "user", "x")))

	require.False(t, MayStart([]byte{0, 0, 0, 1}), "firebird op_connect")
	require.False(t, LooksLikeStartup([]byte{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2f}), "SSLRequest is 8 bytes")
	require.False(t, LooksLikeStartup(startup(2<<16, "user", "x")), "protocol 2 is not routed")
	require.False(t, LooksLikeStartup([]byte{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e}), "CancelRequest is not routed")
	require.False(t, LooksLikeStartup(sslRequest[:7]))
}

func TestBuildAuthMD5(t *testing.T) {
	require.Equal(t,
		[]byte{'R', 0, 0, 0, 12, 0, 0, 0, 5, 0xde, 0xad, 0xbe, 0xef},
		BuildAuthMD5([4]byte{0xde, 0xad, 0xbe, 0xef}))
}

func TestBuildNegotiateProtocolVersion(t *testing.T) {
	require.Equal(t,
		[]byte("v\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x01_pq_.foo\x00"),
		BuildNegotiateProtocolVersion([]string{"_pq_.foo"}))
	require.Equal(t, []string{"_pq_.foo"}, UnsupportedOptions([]Param{{"user", "x"}, {"_pq_.foo", "1"}}))
}

func TestBuildPasswordFailed(t *testing.T) {
	body := "SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed for user \"postgres\"\x00" +
		"Fauth.c\x00L330\x00Rauth_failed\x00\x00"
	want := append([]byte{'E'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))...)
	require.Equal(t, append(want, body...), PasswordFailed("postgres").Build())
}

func TestErrorMessages(t *testing.T) {
	require.Equal(t, "unsupported frontend protocol 1234.5679: server supports 3.0 to 3.0", UnsupportedProtocol(1234, 5679).Message)
	require.Equal(t, StateInvalidAuthorization, NoUser().Code)
	require.Equal(t, "expected password response, got message type 81", ExpectedPassword('Q').Message)
}
