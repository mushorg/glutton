package helpers

import (
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
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
		JA3:  "2196848d251b217de8b2c037e356c11d",
		JA3N: "b7ccbdce26a8fceae75284808afcc065",
		JA4:  "t13i131000_f57a46bbacb6_ab7e3b40a677",
		JA4R: "t13i131000_1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,002b,0032,0033,ff01_0804,0403,0807,0805,0806,0401,0501,0601,0503,0603",
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

type testExt struct {
	typ  uint16
	data []byte
}

// buildHello frames a ClientHello with the given fields in one handshake record.
func buildHello(t *testing.T, legacy uint16, ciphers []uint16, exts []testExt) []byte {
	t.Helper()
	var hs cryptobyte.Builder
	hs.AddUint8(handshakeTypeClientHello)
	hs.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(legacy)
		b.AddBytes(make([]byte, 32))
		b.AddUint8(0) // empty session ID
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, c := range ciphers {
				b.AddUint16(c)
			}
		})
		b.AddUint8(1)
		b.AddUint8(0) // null compression
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range exts {
				b.AddUint16(e.typ)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.data) })
			}
		})
	})
	return records(t, hs.BytesOrPanic(), len(hs.BytesOrPanic()))
}

// records frames handshake bytes into handshake records of at most size bytes.
func records(t *testing.T, hs []byte, size int) []byte {
	t.Helper()
	var out []byte
	for len(hs) > 0 {
		n := min(size, len(hs))
		out = append(out, recordTypeHandshake, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

func extBytes(f func(b *cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	f(&b)
	return b.BytesOrPanic()
}

func sniExt(name string) testExt {
	return testExt{extServerName, extBytes(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(sniHostName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(name)) })
		})
	})}
}

func alpnExt(protos ...string) testExt {
	return testExt{extALPN, extBytes(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, p := range protos {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
			}
		})
	})}
}

func uint16ListExt(typ uint16, values ...uint16) testExt {
	return testExt{typ, extBytes(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, v := range values {
				b.AddUint16(v)
			}
		})
	})}
}

func versionsExt(values ...uint16) testExt {
	return testExt{extSupportedVersions, extBytes(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, v := range values {
				b.AddUint16(v)
			}
		})
	})}
}

// foxioHello is a Chrome-like ClientHello (GREASE included) built to match
// the example in the FoxIO JA4 README.
func foxioHello(t *testing.T) []byte {
	t.Helper()
	ciphers := []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	exts := []testExt{
		{0x1a1a, nil},
		sniExt("example.com"),
		{0x0017, nil},
		{0xff01, []byte{0}},
		uint16ListExt(extSupportedGroups, 0x2a2a, 0x001d, 0x0017, 0x0018),
		{extECPointFormats, []byte{1, 0}},
		{0x0023, nil},
		alpnExt("h2", "http/1.1"),
		{0x0005, []byte{1, 0, 0, 0, 0}},
		uint16ListExt(extSignatureAlgorithms, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
		{0x0012, nil},
		{0x0033, nil},
		{0x002d, []byte{1, 1}},
		versionsExt(0x3a3a, 0x0304, 0x0303),
		{0x001b, nil},
		{0x4469, nil},
		{0x0015, nil},
		{0x4a4a, []byte{0}},
	}
	return buildHello(t, tls.VersionTLS12, ciphers, exts)
}

func TestParseClientHelloFoxIOExample(t *testing.T) {
	hello, ok := ParseClientHello(foxioHello(t))
	require.True(t, ok)
	require.Equal(t, "TLS 1.3", hello.Version)
	require.Equal(t, "example.com", hello.SNI)
	require.Equal(t, []string{"h2", "http/1.1"}, hello.ALPN)
	require.Equal(t, "t13d1516h2_8daaf6152771_e5627efa2ab1", hello.JA4)
	require.Equal(t, "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601", hello.JA4R)
}

func TestJA3NIgnoresExtensionOrder(t *testing.T) {
	ciphers := []uint16{0x1301, 0xc02b}
	a := []testExt{sniExt("a.example"), uint16ListExt(extSupportedGroups, 0x001d, 0x0017), {extECPointFormats, []byte{1, 0}}, {0x0017, nil}}
	b := []testExt{a[3], a[2], a[1], a[0]}
	ha, ok := ParseClientHello(buildHello(t, tls.VersionTLS12, ciphers, a))
	require.True(t, ok)
	hb, ok := ParseClientHello(buildHello(t, tls.VersionTLS12, ciphers, b))
	require.True(t, ok)
	require.NotEqual(t, ha.JA3, hb.JA3)
	require.Equal(t, ha.JA3N, hb.JA3N)
	require.Equal(t, ha.JA4, hb.JA4)
	require.Equal(t, md5Hex("771,4865-49195,0-10-11-23,29-23,0"), ha.JA3N)
}

func TestParseClientHelloFragmented(t *testing.T) {
	whole := foxioHello(t)
	want, ok := ParseClientHello(whole)
	require.True(t, ok)
	for _, size := range []int{1, 3, 4, 50, 200} {
		got, ok := ParseClientHello(records(t, whole[recordHeaderLen:], size))
		require.True(t, ok, "records of %d bytes", size)
		require.Equal(t, want, got, "records of %d bytes", size)
	}
}

// Hellos crypto/tls refuses to parse still get a fingerprint.
func TestParseClientHelloLenient(t *testing.T) {
	ciphers := []uint16{0x1301, 0xc02f}
	for name, tc := range map[string]struct {
		exts []testExt
		sni  string
		alpn []string
	}{
		"duplicate extension": {exts: []testExt{sniExt("a.example"), {0x0017, nil}, {0x0017, nil}}, sni: "a.example"},
		"sni trailing dot":    {exts: []testExt{sniExt("a.example.")}, sni: "a.example."},
		"malformed alpn":      {exts: []testExt{{extALPN, []byte{0x00, 0x09, 0x02, 'h'}}, sniExt("a.example")}, sni: "a.example"},
		"duplicate sni":       {exts: []testExt{sniExt("first.example"), sniExt("second.example"), alpnExt("h2")}, sni: "first.example", alpn: []string{"h2"}},
	} {
		t.Run(name, func(t *testing.T) {
			hello, ok := ParseClientHello(buildHello(t, tls.VersionTLS12, ciphers, tc.exts))
			require.True(t, ok)
			require.Equal(t, tc.sni, hello.SNI)
			require.Equal(t, tc.alpn, hello.ALPN)
			require.Len(t, hello.Extensions, len(tc.exts))
			require.Regexp(t, `^t12d02\d{2}`, hello.JA4)
		})
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	hello, ok := ParseClientHello(buildHello(t, tls.VersionTLS10, []uint16{0x002f}, nil))
	require.True(t, ok)
	require.Equal(t, "TLS 1.0", hello.Version)
	require.Equal(t, "t10i010000_ba72b8082249_000000000000", hello.JA4)
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(loadGoHelloF(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		hello, ok := ParseClientHello(data)
		if ok && (len(hello.JA3) != 32 || len(hello.JA3N) != 32 || len(hello.JA4) != 36) {
			t.Fatalf("bad fingerprint %+v", hello)
		}
	})
}

func loadGoHelloF(f *testing.F) []byte {
	data, err := os.ReadFile("testdata/clienthello_go_mlkem.bin")
	if err != nil {
		f.Fatal(err)
	}
	return data
}
