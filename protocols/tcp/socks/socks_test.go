package socks

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SOCKS4a CONNECT httpbin.org:80 from Ochi event
// 2e27fe0b-5593-4090-bc5b-fddebc9666c6 (tcp/5678).
var socks4aHttpbin = []byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00httpbin.org\x00")

func reader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func TestReadSOCKS4aCapturedEvent(t *testing.T) {
	r := reader(socks4aHttpbin)
	v, err := ReadVersion(r)
	require.NoError(t, err)
	require.Equal(t, byte(Version4), v)

	req, err := ReadSOCKS4(r)
	require.NoError(t, err)
	require.Equal(t, Request{
		Version: Version4,
		Command: CmdConnect,
		Host:    "httpbin.org",
		Port:    80,
		SOCKS4a: true,
		Raw:     socks4aHttpbin,
	}, req)
	require.Equal(t, "socks4a-connect", req.Name())
	require.Equal(t, "httpbin.org:80", req.Addr())
}

func TestReadSOCKS4WithUser(t *testing.T) {
	data := []byte("\x04\x01\x01\xbb\xc0\x00\x02\x01root\x00")
	r := reader(data[1:])
	req, err := ReadSOCKS4(r)
	require.NoError(t, err)
	require.False(t, req.SOCKS4a)
	require.Equal(t, "192.0.2.1", req.Host)
	require.Equal(t, uint16(443), req.Port)
	require.Equal(t, "root", req.User)
	require.Equal(t, "socks4-connect", req.Name())
	require.Equal(t, data, req.Raw)
}

func TestReadSOCKS4Errors(t *testing.T) {
	// truncated header keeps the bytes read so far
	req, err := ReadSOCKS4(reader([]byte("\x01\x00")))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, []byte("\x04\x01\x00"), req.Raw)

	long := append([]byte("\x01\x00\x50\x01\x02\x03\x04"), []byte(strings.Repeat("A", 300))...)
	_, err = ReadSOCKS4(reader(long))
	require.ErrorIs(t, err, ErrFieldTooLong)

	// SOCKS4a without a hostname terminator
	_, err = ReadSOCKS4(reader([]byte("\x01\x00\x50\x00\x00\x00\x01\x00host")))
	require.ErrorIs(t, err, io.EOF)
}

func TestReadGreetingAuthRequest(t *testing.T) {
	r := reader([]byte("\x02\x00\x02"))
	g, err := ReadGreeting(r)
	require.NoError(t, err)
	require.Equal(t, []byte{MethodNoAuth, MethodUserPass}, g.Methods)
	require.Equal(t, []byte("\x05\x02\x00\x02"), g.Raw)

	_, err = ReadGreeting(reader([]byte("\x00")))
	require.ErrorIs(t, err, ErrNoMethods)

	auth, err := ReadAuth(reader([]byte("\x01\x05admin\x06s3cret")))
	require.NoError(t, err)
	require.Equal(t, "admin", auth.User)
	require.Equal(t, []byte("\x01\x05admin\x06******"), auth.Raw)
	require.NotContains(t, string(auth.Raw), "s3cret")

	_, err = ReadAuth(reader([]byte("\x05\x01\x00")))
	require.ErrorIs(t, err, ErrBadAuthVer)

	req, err := ReadSOCKS5(reader([]byte("\x05\x01\x00\x03\x0bhttpbin.org\x00\x50")))
	require.NoError(t, err)
	require.Equal(t, "httpbin.org", req.Host)
	require.Equal(t, uint16(80), req.Port)
	require.Equal(t, "socks5-connect", req.Name())

	req, err = ReadSOCKS5(reader([]byte("\x05\x01\x00\x01\xc0\x00\x02\x01\x01\xbb")))
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1:443", req.Addr())

	req, err = ReadSOCKS5(reader(append([]byte("\x05\x03\x00\x04"), append(net.ParseIP("2001:db8::1"), 0, 53)...)))
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::1]:53", req.Addr())
	require.Equal(t, "socks5-udp-associate", req.Name())

	_, err = ReadSOCKS5(reader([]byte("\x05\x01\x00\x09")))
	require.ErrorIs(t, err, ErrBadAddrType)
	_, err = ReadSOCKS5(reader([]byte("\x04\x01\x00\x01")))
	require.ErrorIs(t, err, ErrVersion)
}

func TestSelectMethod(t *testing.T) {
	require.Equal(t, byte(MethodUserPass), SelectMethod([]byte{0x00, 0x02}))
	require.Equal(t, byte(MethodNoAuth), SelectMethod([]byte{0x00}))
	require.Equal(t, byte(MethodNoAcceptable), SelectMethod([]byte{0x01, 0x80}))
}

func TestReplies(t *testing.T) {
	require.Equal(t, []byte{0x00, 0x5a, 0x9c, 0x40, 1, 2, 3, 4}, Reply4(Reply4Granted, net.IPv4(1, 2, 3, 4), 40000))
	require.Equal(t, []byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0}, Reply4(Reply4Rejected, nil, 0))
	require.Equal(t, []byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x9c, 0x40}, Reply5(Reply5Succeeded, net.IPv4(1, 2, 3, 4), 40000))
	require.Equal(t, []byte{0x05, 0x02}, MethodReply(MethodUserPass))
	require.Equal(t, []byte{0x01, 0x00}, AuthReply(0))
}

func TestLooksLikeSOCKS(t *testing.T) {
	for name, data := range map[string][]byte{
		"captured socks4a": socks4aHttpbin,
		"socks4 userid":    []byte("\x04\x01\x01\xbb\xc0\x00\x02\x01root\x00"),
		"socks4 bind":      []byte("\x04\x02\x01\xbb\xc0\x00\x02\x01\x00"),
		"socks5 no-auth":   {0x05, 0x01, 0x00},
		"socks5 multi":     {0x05, 0x03, 0x00, 0x01, 0x02},
		"socks5 private":   {0x05, 0x01, 0x80},
	} {
		require.True(t, LooksLikeSOCKS(data), name)
	}
	for name, data := range map[string][]byte{
		"short":              {0x05, 0x01},
		"socks5 extra":       {0x05, 0x01, 0x00, 0x00},
		"socks5 zero":        {0x05, 0x00, 0x00},
		"socks5 bad method":  {0x05, 0x01, 0x42},
		"socks4 no nul":      []byte("\x04\x01\x00\x50\x01\x02\x03\x04root"),
		"socks4 bad cmd":     []byte("\x04\x03\x00\x50\x01\x02\x03\x04\x00"),
		"socks4 zero port":   []byte("\x04\x01\x00\x00\x01\x02\x03\x04\x00"),
		"socks4 zero ip":     []byte("\x04\x01\x00\x50\x00\x00\x00\x00\x00"),
		"socks4 trailing":    []byte("\x04\x01\x00\x50\x01\x02\x03\x04\x00GET"),
		"socks4a empty host": []byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00\x00"),
		"socks4a no host":    []byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00"),
		"mongodb header":     {0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00},
		"http":               []byte("GET / HTTP/1.1\r\n\r\n"),
		"tls":                {0x16, 0x03, 0x01, 0x00, 0x05},
	} {
		require.False(t, LooksLikeSOCKS(data), name)
	}
}
