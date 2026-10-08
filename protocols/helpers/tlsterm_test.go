package helpers

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
	}
	go func() {
		c, info, err := TerminateTLS(server)
		gotInfo.name, gotInfo.alpn, gotInfo.ver, gotInfo.hello = info.ServerName, info.ALPN, info.Version, info.Hello
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
