package helpers

import (
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// clienthello_go_mlkem.bin is the ClientHello from Ochi event
// 5c99acb5-9d55-4846-90e7-30a6b2c0a135: Go-style, no SNI, X25519MLKEM768.
func loadGoHello(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/clienthello_go_mlkem.bin")
	require.NoError(t, err)
	return data
}

func TestParseClientHelloCaptured(t *testing.T) {
	hello, ok := ParseClientHello(loadGoHello(t))
	require.True(t, ok)
	require.Equal(t, &ClientHello{
		Version:      "TLS 1.3",
		CipherSuites: []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x1301, 0x1302, 0x1303},
		Extensions:   []uint16{11, 65281, 23, 18, 5, 10, 13, 50, 43, 51},
		Groups:       []uint16{0x11ec, 29, 23, 24, 25},
		// cross-checked with tshark tls.handshake.ja3
		JA3: "2196848d251b217de8b2c037e356c11d",
		JA4: "t13i131000_f57a46bbacb6_ab7e3b40a677",
	}, hello)
}

// clientHelloFrom captures the ClientHello a crypto/tls client sends.
func clientHelloFrom(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	require.NoError(t, server.SetDeadline(time.Now().Add(2*time.Second)))
	go func() {
		_ = tls.Client(client, cfg).Handshake()
		client.Close()
	}()
	var data []byte
	buf := make([]byte, 4096)
	for {
		n, err := server.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil || len(data) >= 5 && len(data) >= 5+int(data[3])<<8|int(data[4]) {
			return data
		}
	}
}

func TestParseClientHelloSNIAndALPN(t *testing.T) {
	data := clientHelloFrom(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
	hello, ok := ParseClientHello(data)
	require.True(t, ok)
	require.Equal(t, "example.com", hello.SNI)
	require.Equal(t, []string{"h2", "http/1.1"}, hello.ALPN)
	require.Equal(t, "TLS 1.3", hello.Version)
	require.Regexp(t, `^t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`, hello.JA4)
	require.Len(t, hello.JA3, 32)
}

func TestParseClientHelloTLS12Only(t *testing.T) {
	data := clientHelloFrom(t, &tls.Config{ServerName: "example.com", MaxVersion: tls.VersionTLS12})
	hello, ok := ParseClientHello(data)
	require.True(t, ok)
	require.Equal(t, "TLS 1.2", hello.Version)
	require.Regexp(t, `^t12d\d{4}00_`, hello.JA4)
}

func TestParseClientHelloTruncated(t *testing.T) {
	data := loadGoHello(t)
	for n := 0; n < len(data); n++ {
		_, ok := ParseClientHello(data[:n])
		require.False(t, ok, "prefix of %d bytes", n)
	}
}

func TestParseClientHelloGarbage(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, // ServerHello type
		{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff},
	} {
		_, ok := ParseClientHello(data)
		require.False(t, ok, "%x", data)
	}
}

func TestIsGREASE(t *testing.T) {
	require.True(t, isGREASE(0x0a0a))
	require.True(t, isGREASE(0xfafa))
	require.False(t, isGREASE(0x0a1a))
	require.False(t, isGREASE(0x1301))
}

func TestJA4ALPN(t *testing.T) {
	require.Equal(t, "00", ja4ALPN(nil))
	require.Equal(t, "h2", ja4ALPN([]string{"h2"}))
	require.Equal(t, "h1", ja4ALPN([]string{"http/1.1"}))
	require.Equal(t, "ab", ja4ALPN([]string{"\xab"}))
	require.Equal(t, "20", ja4ALPN([]string{"\x20\x30"}))
}
