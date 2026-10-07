package helpers

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"io"
	"net"

	"github.com/mushorg/glutton/connection"
)

// tlsCertName is the subject of the shared self-signed server certificate.
const tlsCertName = "localhost"

// TLSHelloLimit caps how many ClientHello bytes are kept.
const TLSHelloLimit = 4096

// helloRecorder copies up to limit bytes read through it.
type helloRecorder struct {
	r         io.Reader
	buf       []byte
	limit     int
	truncated bool
}

func (c *helloRecorder) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		room := c.limit - len(c.buf)
		if n > room {
			c.truncated = true
		}
		c.buf = append(c.buf, b[:max(0, min(n, room))]...)
	}
	return n, err
}

// recordedConn reads through the recorder and writes to the raw connection.
type recordedConn struct {
	net.Conn
	r io.Reader
}

func (c *recordedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// TerminateTLS runs a server-side TLS handshake on conn with a self-signed
// certificate. On success it returns the decrypted connection. The returned
// info always holds whatever the client sent (capped at TLSHelloLimit), so a
// failed handshake still tells the caller what the client wanted.
func TerminateTLS(conn net.Conn) (net.Conn, *connection.TLSInfo, error) {
	return TerminateTLSFrom(conn, conn)
}

// TerminateTLSFrom is TerminateTLS for a connection whose inbound bytes were
// partly consumed already: handshake reads come from r (for example a
// bufio.Reader over conn, or a STARTTLS upgrade) and writes go to conn.
func TerminateTLSFrom(conn net.Conn, r io.Reader) (net.Conn, *connection.TLSInfo, error) {
	info := &connection.TLSInfo{}
	cert, err := SelfSignedCertificate(pkix.Name{CommonName: tlsCertName}, tlsCertName)
	if err != nil {
		return nil, info, err
	}
	rec := &helloRecorder{r: r, limit: TLSHelloLimit}
	tlsConn := tls.Server(&recordedConn{Conn: conn, r: rec}, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			info.ServerName = hello.ServerName
			info.ALPN = append([]string(nil), hello.SupportedProtos...)
			return nil, nil
		},
	})
	err = tlsConn.Handshake()
	info.Hello = rec.buf
	info.Truncated = rec.truncated
	if err != nil {
		return nil, info, err
	}
	state := tlsConn.ConnectionState()
	info.Version = tls.VersionName(state.Version)
	info.Cipher = tls.CipherSuiteName(state.CipherSuite)
	return tlsConn, info, nil
}
