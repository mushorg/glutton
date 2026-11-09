package helpers

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfSignedCertificateForHost(t *testing.T) {
	dnsCert, err := SelfSignedCertificateForHost("ipv4.icanhazip.com")
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(dnsCert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "ipv4.icanhazip.com", leaf.Subject.CommonName)
	require.NoError(t, leaf.VerifyHostname("ipv4.icanhazip.com"))

	ipCert, err := SelfSignedCertificateForHost("198.51.100.10")
	require.NoError(t, err)
	ipLeaf, err := x509.ParseCertificate(ipCert.Certificate[0])
	require.NoError(t, err)
	require.NoError(t, ipLeaf.VerifyHostname("198.51.100.10"))

	fallback, err := SelfSignedCertificateForHost("")
	require.NoError(t, err)
	fbLeaf, err := x509.ParseCertificate(fallback.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, SensorCertName(), fbLeaf.Subject.CommonName)
}

func TestSelfSignedCertificateForHostSharedKeyBounded(t *testing.T) {
	// tunnel SNI and CONNECT targets are attacker chosen: a flood rotating
	// hosts must not generate an RSA key per host or grow the cache forever
	prev := hostCertMax
	hostCertMax = 2
	t.Cleanup(func() { hostCertMax = prev })

	a, err := SelfSignedCertificateForHost("gunceladreslergiris3.com")
	require.NoError(t, err)
	b, err := SelfSignedCertificateForHost("172.67.195.214")
	require.NoError(t, err)
	require.Equal(t, a.PrivateKey, b.PrivateKey, "host certificates share one key")
	require.NotEqual(t, a.Certificate[0], b.Certificate[0])

	again, err := SelfSignedCertificateForHost("gunceladreslergiris3.com")
	require.NoError(t, err)
	require.Equal(t, a.Certificate[0], again.Certificate[0], "cached per host")

	_, err = SelfSignedCertificateForHost("musyokimusyoka.com")
	require.NoError(t, err)
	hostCerts.Lock()
	n := hostCerts.order.Len()
	_, evicted := hostCerts.index["ip:172.67.195.214"]
	hostCerts.Unlock()
	require.LessOrEqual(t, n, 2)
	require.False(t, evicted, "least recently used host is dropped first")
}

func TestTerminateTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	type result struct {
		conn net.Conn
		err  error
	}
	res := make(chan result, 1)
	var gotInfo struct {
		name  string
		alpn  []string
		ver   string
		hello []byte
		ja3   string
		ja4   string
	}
	go func() {
		c, info, err := TerminateTLS(server)
		gotInfo.name, gotInfo.alpn, gotInfo.ver, gotInfo.hello = info.ServerName, info.ALPN, info.Version, info.Hello
		gotInfo.ja3, gotInfo.ja4 = info.JA3, info.JA4
		res <- result{c, err}
	}()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com", NextProtos: []string{"pop3"}})
	require.NoError(t, tc.Handshake())
	r := <-res
	require.NoError(t, r.err)
	require.Equal(t, "mail.example.com", gotInfo.name)
	require.Equal(t, []string{"pop3"}, gotInfo.alpn)
	require.NotEmpty(t, gotInfo.ver)
	require.Equal(t, byte(0x16), gotInfo.hello[0])
	require.Len(t, gotInfo.ja3, 32)
	require.Regexp(t, `^t13d\d{4}p3_[0-9a-f]{12}_[0-9a-f]{12}$`, gotInfo.ja4)

	go func() { _, _ = r.conn.Write([]byte("hi")) }()
	buf := make([]byte, 2)
	_, err := tc.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hi", string(buf))
}

func TestTerminateTLSNonTLSClient(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() { _, _ = client.Write([]byte("USER bob\r\nPASS x\r\n")) }()
	_, info, err := TerminateTLS(server)
	require.Error(t, err)
	require.Equal(t, []byte("USER bob\r\nPASS x\r\n"), info.Hello)
	require.Empty(t, info.JA3)
	require.Empty(t, info.JA4)
}

// A hello crypto/tls rejects fails the handshake but is still fingerprinted.
func TestTerminateTLSFingerprintsRejectedHello(t *testing.T) {
	hello := buildHello(t, tls.VersionTLS12, []uint16{0x1301, 0xc02f},
		[]testExt{sniExt("a.example"), {0x0017, nil}, {0x0017, nil}, versionsExt(0x0304, 0x0303)})
	want, ok := ParseClientHello(hello)
	require.True(t, ok)

	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	go func() {
		_, _ = client.Write(hello)
		_, _ = io.Copy(io.Discard, client) // the alert
	}()
	_, info, err := TerminateTLS(server)
	require.Error(t, err)
	require.Equal(t, want.JA3, info.JA3)
	require.Equal(t, want.JA3N, info.JA3N)
	require.Equal(t, want.JA4, info.JA4)
	require.Equal(t, want.JA4R, info.JA4R)
	require.Regexp(t, `^t13d0204`, info.JA4)
}

// serverHelloRandomTail sends hello to TerminateTLS and returns the last 8
// bytes of the ServerHello random.
func serverHelloRandomTail(t *testing.T, hello []byte, version uint16) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	go func() {
		_, _, _ = TerminateTLS(server)
		_ = server.Close()
	}()
	_, err := client.Write(hello)
	require.NoError(t, err)
	// record header (5) + handshake header (4) + version (2) + random (32)
	resp := make([]byte, 43)
	_, err = io.ReadFull(client, resp)
	require.NoError(t, err)
	require.Equal(t, byte(0x16), resp[0], "handshake record")
	require.Equal(t, byte(0x02), resp[5], "ServerHello")
	require.Equal(t, []byte{byte(version >> 8), byte(version)}, resp[9:11], "negotiated version")
	return resp[35:43]
}

// RFC 8446 §4.1.3: a TLS 1.3 capable server that negotiates TLS 1.2 sets the
// DOWNGRD\x01 sentinel whatever the client offered, as OpenSSL does. Captured
// scanners (ja4 t12i880600, no supported_versions) see the same sentinel a
// stock nginx/OpenSSL server would send them, so it is not a sensor tell.
func TestTerminateTLSDowngradeSentinel(t *testing.T) {
	common := []testExt{
		uint16ListExt(extSupportedGroups, 0x0017, 0x0018),
		{extECPointFormats, []byte{1, 0}},
		uint16ListExt(extSignatureAlgorithms, 0x0401, 0x0804, 0x0403),
	}
	sentinel := []byte("DOWNGRD\x01")

	legacy := buildHello(t, tls.VersionTLS12, []uint16{0xc02f, 0x009c}, common)
	require.Equal(t, sentinel, serverHelloRandomTail(t, legacy, tls.VersionTLS12), "no supported_versions")

	offered := buildHello(t, tls.VersionTLS12, []uint16{0xc02f, 0x009c},
		append(append([]testExt{}, common...), versionsExt(0x0303)))
	require.Equal(t, sentinel, serverHelloRandomTail(t, offered, tls.VersionTLS12), "supported_versions without 1.3")

	// TLS 1.0 (kept for old RDP clients) carries the DOWNGRD\x00 variant.
	old := buildHello(t, tls.VersionTLS10, []uint16{0xc013, 0x002f}, common[:2])
	require.Equal(t, []byte("DOWNGRD\x00"), serverHelloRandomTail(t, old, tls.VersionTLS10))
}

// A TLS 1.2-only ClientHello with no supported_versions extension (shape of
// the captured ja4 t12i130500_2d7513195f68_e51b7354d87f sweep on tcp/12104-12109
// and tcp/12225) gets the complete ECDHE-RSA server flight in one write:
// ServerHello, Certificate, ServerKeyExchange, ServerHelloDone. The sensor then
// waits for the client's key exchange, so a close right after this write is the
// client giving up (e.g. on the self-signed certificate), not a short flight.
func TestTerminateTLS12OnlyFullFlight(t *testing.T) {
	hello := buildHello(t, tls.VersionTLS12, []uint16{0xc02f, 0xc030, 0xc013, 0xc014, 0x009c, 0x002f, 0x0035},
		[]testExt{
			uint16ListExt(extSupportedGroups, 0x001d, 0x0017, 0x0018),
			{extECPointFormats, []byte{1, 0}},
			uint16ListExt(extSignatureAlgorithms, 0x0401, 0x0804, 0x0403, 0x0201),
		})
	parsed, ok := ParseClientHello(hello)
	require.True(t, ok)
	require.Regexp(t, `^t12i07`, parsed.JA4)

	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() {
		_, _, err := TerminateTLS(server)
		done <- err
	}()
	_, err := client.Write(hello)
	require.NoError(t, err)

	// net.Pipe hands over one Write per Read, so this is the first write only.
	buf := make([]byte, 16<<10)
	n, err := client.Read(buf)
	require.NoError(t, err)
	flight := buf[:n]

	var types []byte
	for len(flight) > 0 {
		require.GreaterOrEqual(t, len(flight), 5)
		require.Equal(t, byte(0x16), flight[0], "handshake record")
		require.Equal(t, []byte{0x03, 0x03}, flight[1:3], "TLS 1.2 record version")
		l := int(flight[3])<<8 | int(flight[4])
		require.GreaterOrEqual(t, len(flight), 5+l)
		body := flight[5 : 5+l]
		for len(body) > 0 {
			require.GreaterOrEqual(t, len(body), 4)
			hl := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
			require.GreaterOrEqual(t, len(body), 4+hl)
			types = append(types, body[0])
			body = body[4+hl:]
		}
		flight = flight[5+l:]
	}
	require.Equal(t, []byte{2, 11, 12, 14}, types, "ServerHello, Certificate, ServerKeyExchange, ServerHelloDone")

	// The client hanging up here is what the captured sessions show.
	require.NoError(t, client.Close())
	require.Error(t, <-done)
}

func TestTerminateTLSSilentClient(t *testing.T) {
	client, server := net.Pipe()
	require.NoError(t, client.Close())
	_, info, err := TerminateTLS(server)
	require.Error(t, err)
	require.Empty(t, info.Hello)
}

func TestTerminateTLSHelloCap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		// a TLS record header claiming a large handshake, followed by filler
		buf := make([]byte, 2*TLSHelloLimit)
		copy(buf, []byte{0x16, 0x03, 0x01, 0x40, 0x00})
		_, _ = client.Write(buf)
	}()
	require.NoError(t, server.SetDeadline(time.Now().Add(2*time.Second)))
	_, info, err := TerminateTLS(server)
	require.Error(t, err)
	require.LessOrEqual(t, len(info.Hello), TLSHelloLimit)
}

func TestTerminateTLSFromBufferedReader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(server)

	done := make(chan error, 1)
	go func() {
		_, err := br.Peek(1) // a handler peeks before deciding to terminate TLS
		if err == nil {
			_, _, err = TerminateTLSFrom(server, br)
		}
		done <- err
	}()
	require.NoError(t, tls.Client(client, &tls.Config{InsecureSkipVerify: true}).Handshake())
	require.NoError(t, <-done)
}

func TestTerminateTLSFromWith(t *testing.T) {
	// Use SelfSignedCertificateRDP to verify TerminateTLSFromWith accepts a custom cert.
	cert, err := SelfSignedCertificateRDP("WIN-TESTNODE")
	require.NoError(t, err)

	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	res := make(chan error, 1)
	go func() {
		_, _, err := TerminateTLSFromWith(cert, server, server)
		res <- err
	}()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tc.Handshake())
	_ = tc.Close()
	require.NoError(t, <-res)
}

// ecdsaOnlyHello is a TLS 1.3 ClientHello captured on tcp/6036: its
// signature_algorithms list only ed448, ed25519 and ECDSA schemes (no RSA), so
// an RSA-only server answered it with a fatal handshake_failure alert.
const ecdsaOnlyHello = "FgMBAkIBAAI+AwNkenWsFwDcNuSvRCgL4l1A3QwW9dYo4SJKesPwn/cbXiA0pk9yIN8ZBR22Vnhc6z9EDcGgQmnXmJlZk6w7sqqxqQAGEwMTAhMBAQAB7wArAAMCAwQACgAGAAQAFwAdADMARwBFABcAQQS3+6b49M48S2Omw1PCKYERz04xUHhczSLFqA8GuWkpjfXRDGcuX13KzexnkiZb8MzucPak8Uuey9iuLYWaEkGWAA0ADAAKCAgIBwYDBQMEAwAQAXkBdwhodHRwLzAuOQhodHRwLzEuMAZzcGR5LzEGc3BkeS8yBnNwZHkvMwlzdHVuLnR1cm4Sc3R1bi5uYXQtZGlzY292ZXJ5A2gyYwZ3ZWJydGMIYy13ZWJydGMDZnRwBGltYXAEcG9wMwttYW5hZ2VzaWV2ZQRjb2FwAmNvC3htcHAtY2xpZW50C3htcHAtc2VydmVyCmFjbWUtdGxzLzEEbXF0dANkb3QHbnRza2UvMQZzdW5ycGMDc21iA2lyYwRubnRwBG5uc3ADZG9xBXNpcC8yB3Rkcy84LjAFZGljb20JcG9zdHJlc3FsCnJhZGl1cy8xLjAKcmFkaXVzLzEuMRRuZXRwZXJmbWV0ZXIvY29udHJvbBFuZXRwZXJmbWV0ZXIvZGF0YQZsaWJwMnADcXJ0AndxBHBlcmYDbW9xBG1vcXQGaDMtZXh0CmhxLWludGVyb3AHaDMtUTA0NgVoMy0yNwVoMy0yOQJoMwJoMghodHRwLzEuMQA6AAIEAA=="

// ecdsaSuitesHello is a TLS 1.2 ClientHello captured on tcp/7999 (ja4
// t12d3511h9_66c735deec94_52c4d8bb91c9, SNI 221-166-172-163.instances.scw.cloud).
// Its only ECDHE_RSA suite is 3DES (c012), which crypto/tls no longer enables
// by default, while it offers ECDHE_ECDSA AES/ChaCha suites. Because the SNI
// did not match the self-signed certificates, the picker rejected both and fell
// back to RSA, which ended in a fatal handshake_failure alert.
var ecdsaSuitesHello = []byte{
	0x16, 0x03, 0x03, 0x01, 0x6d, 0x01, 0x00, 0x01, 0x69, 0x03, 0x03, 0x39, 0x4a, 0x9d, 0x7f, 0x31,
	0xee, 0x1e, 0x21, 0xe5, 0x9e, 0x91, 0x0f, 0x4c, 0x01, 0xfc, 0xce, 0x4e, 0x26, 0x9e, 0xb1, 0x6a,
	0xc9, 0xdf, 0xa8, 0x77, 0x13, 0x25, 0x0f, 0x77, 0x98, 0xe2, 0x92, 0x20, 0x7e, 0xf1, 0xaa, 0x02,
	0xde, 0xae, 0x06, 0x3e, 0x00, 0x73, 0x12, 0x17, 0xb4, 0x67, 0xb9, 0xfd, 0x69, 0x35, 0x47, 0x08,
	0x23, 0x19, 0x53, 0xef, 0x3d, 0xeb, 0x3f, 0xcb, 0x6f, 0x7e, 0x24, 0x2a, 0x00, 0x46, 0xc0, 0x12,
	0xc0, 0x07, 0xcc, 0x14, 0x13, 0x01, 0x13, 0x02, 0xcc, 0xa9, 0xc0, 0x73, 0xc0, 0x72, 0xc0, 0x2c,
	0xc0, 0xaf, 0xc0, 0xad, 0xc0, 0x24, 0xc0, 0x0a, 0xc0, 0x2b, 0xc0, 0xae, 0xc0, 0xac, 0xc0, 0x23,
	0xc0, 0x09, 0xc0, 0x08, 0x00, 0x9a, 0x00, 0xc4, 0x00, 0x88, 0x00, 0xbe, 0x00, 0x45, 0x00, 0x9f,
	0xc0, 0xa3, 0xc0, 0x9f, 0x00, 0x6b, 0x00, 0x39, 0x00, 0x9e, 0xc0, 0xa2, 0xc0, 0x9e, 0x00, 0x67,
	0x00, 0x33, 0x00, 0x16, 0x01, 0x00, 0x00, 0xda, 0x00, 0x00, 0x00, 0x28, 0x00, 0x26, 0x00, 0x00,
	0x23, 0x32, 0x32, 0x31, 0x2d, 0x31, 0x36, 0x36, 0x2d, 0x31, 0x37, 0x32, 0x2d, 0x31, 0x36, 0x33,
	0x2e, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x77, 0x2e, 0x63,
	0x6c, 0x6f, 0x75, 0x64, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xff, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
	0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x3c, 0x00, 0x3a,
	0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
	0x2e, 0x30, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x06, 0x73, 0x70, 0x64, 0x79,
	0x2f, 0x31, 0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33,
	0x02, 0x68, 0x32, 0x03, 0x68, 0x32, 0x63, 0x02, 0x68, 0x71, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
	0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
	0x02, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xbf, 0xbb, 0xde, 0x85,
	0xc6, 0x02, 0x85, 0x1a, 0xc6, 0x78, 0x55, 0xb3, 0x8a, 0xa0, 0x2e, 0xe6, 0x1c, 0xd7, 0x42, 0xad,
	0x28, 0xfa, 0xc5, 0x1e, 0x39, 0x6c, 0x37, 0x5a, 0xe3, 0xe1, 0xdc, 0xbf, 0x00, 0x2d, 0x00, 0x02,
	0x01, 0x01,
}

// ecdsaOnlyHelloBytes decodes ecdsaOnlyHello.
func ecdsaOnlyHelloBytes(t *testing.T) []byte {
	t.Helper()
	hello, err := base64.StdEncoding.DecodeString(ecdsaOnlyHello)
	require.NoError(t, err)
	return hello
}

// firstServerRecord sends hello to terminate and returns the first 6 bytes the
// server answers with.
func firstServerRecord(t *testing.T, hello []byte, terminate func(net.Conn)) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	go func() {
		terminate(server)
		_ = server.Close()
	}()
	go func() { _, _ = client.Write(hello) }()

	hdr := make([]byte, 6)
	_, err := io.ReadFull(client, hdr)
	require.NoError(t, err)
	return hdr
}

func TestTerminateTLSECDSAOnlyClient(t *testing.T) {
	rsaCert, err := SelfSignedCertificate(pkix.Name{CommonName: "rsa-only"}, "rsa-only")
	require.NoError(t, err)
	// control: an RSA-only server can only refuse this hello
	hdr := firstServerRecord(t, ecdsaOnlyHelloBytes(t), func(c net.Conn) { _, _, _ = TerminateTLSFromWith(rsaCert, c, c) })
	require.Equal(t, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02}, hdr, "fatal alert")

	// the shared certificate set answers with a ServerHello instead
	hdr = firstServerRecord(t, ecdsaOnlyHelloBytes(t), func(c net.Conn) { _, _, _ = TerminateTLS(c) })
	require.Equal(t, byte(0x16), hdr[0], "handshake record, not an alert")
	require.Equal(t, byte(0x02), hdr[5], "ServerHello")
}

// A TLS 1.2 client that verifies RSA signatures but shares no enabled
// ECDHE_RSA suite with the server gets the ECDSA cert, not handshake_failure.
func TestTerminateTLSECDSASuitesClient(t *testing.T) {
	rsaCert, err := SelfSignedCertificate(pkix.Name{CommonName: "rsa-only"}, "rsa-only")
	require.NoError(t, err)
	hdr := firstServerRecord(t, ecdsaSuitesHello, func(c net.Conn) { _, _, _ = TerminateTLSFromWith(rsaCert, c, c) })
	require.Equal(t, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02}, hdr, "control: RSA-only server refuses")

	hdr = firstServerRecord(t, ecdsaSuitesHello, func(c net.Conn) { _, _, _ = TerminateTLS(c) })
	require.Equal(t, []byte{0x16, 0x03, 0x03}, hdr[:3], "TLS 1.2 handshake record, not an alert")
	require.Equal(t, byte(0x02), hdr[5], "ServerHello")
}

func TestTerminateTLSPrefersRSA(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	res := make(chan error, 1)
	go func() {
		_, _, err := TerminateTLS(server)
		res <- err
	}()
	// an SNI that does not match the sensor cert must not change the choice
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
	require.NoError(t, tc.Handshake())
	leaf := tc.ConnectionState().PeerCertificates[0]
	require.Equal(t, x509.RSA, leaf.PublicKeyAlgorithm, "clients that accept RSA keep getting the RSA cert")
	require.Equal(t, SensorCertName(), leaf.Subject.CommonName)
	require.NotEqual(t, "localhost", leaf.Subject.CommonName)
	require.NoError(t, <-res)
}

func TestSelfSignedCertificateECDSA(t *testing.T) {
	cert, err := SelfSignedCertificateECDSA(pkix.Name{CommonName: "localhost"}, "localhost")
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, x509.ECDSA, leaf.PublicKeyAlgorithm)
	require.Equal(t, x509.KeyUsageDigitalSignature, leaf.KeyUsage)
	again, err := SelfSignedCertificateECDSA(pkix.Name{CommonName: "localhost"}, "localhost")
	require.NoError(t, err)
	require.Equal(t, cert.Certificate[0], again.Certificate[0], "cached per subject")
}

func TestSelfSignedCertificateRDP(t *testing.T) {
	cert, err := SelfSignedCertificateRDP("WIN-ABCDEF12345")
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "WIN-ABCDEF12345", parsed.Subject.CommonName)
	require.Empty(t, parsed.DNSNames, "RDP cert must have no SAN")
	require.False(t, parsed.BasicConstraintsValid, "RDP cert must not include BasicConstraints")
}
