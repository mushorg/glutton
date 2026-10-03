package rdp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// IsTLSRecord reports whether data begins with a TLS record header
// (content type + version 0x03 0x0n).
func IsTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	switch data[0] {
	case 20, 21, 22, 23: // ChangeCipherSpec, Alert, Handshake, ApplicationData
		return data[1] == 0x03 && data[2] <= 0x04
	default:
		return false
	}
}

var (
	stubTLSOnce sync.Once
	stubTLSCert tls.Certificate
	stubTLSErr  error
)

func stubCertificate() (tls.Certificate, error) {
	stubTLSOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			stubTLSErr = err
			return
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			stubTLSErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				Organization: []string{"Microsoft"},
				CommonName:   "rdp",
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			stubTLSErr = err
			return
		}
		stubTLSCert = tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}
	})
	return stubTLSCert, stubTLSErr
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

type writeRecorder struct {
	net.Conn
	buf *bytes.Buffer
}

func (c *writeRecorder) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		_, _ = c.buf.Write(b[:n])
	}
	return n, err
}

// StubTLSHandshake replays firstRecord into a TLS server handshake on conn and
// returns the handshake bytes written (ServerHello, Certificate, …). A
// handshake error after some bytes were written is ignored so callers can still
// record the stub response.
func StubTLSHandshake(conn net.Conn, firstRecord []byte) ([]byte, error) {
	cert, err := stubCertificate()
	if err != nil {
		return nil, err
	}
	var written bytes.Buffer
	wrapped := &prefixConn{
		Conn:   &writeRecorder{Conn: conn, buf: &written},
		prefix: append([]byte(nil), firstRecord...),
	}
	tlsConn := tls.Server(wrapped, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	})
	err = tlsConn.Handshake()
	out := append([]byte(nil), written.Bytes()...)
	if len(out) == 0 {
		return nil, err
	}
	return out, nil
}
