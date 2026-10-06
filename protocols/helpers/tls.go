package helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

type certEntry struct {
	once sync.Once
	cert tls.Certificate
	err  error
}

var selfSignedCerts sync.Map // subject string -> *certEntry

// SelfSignedCertificate returns a self-signed server certificate for subject.
// The key pair is generated once per process and subject, so handlers can call
// it on every connection.
func SelfSignedCertificate(subject pkix.Name, dnsNames ...string) (tls.Certificate, error) {
	v, _ := selfSignedCerts.LoadOrStore(subject.String(), &certEntry{})
	e := v.(*certEntry)
	e.once.Do(func() {
		e.cert, e.err = generateCertificate(subject, dnsNames)
	})
	return e.cert, e.err
}

func generateCertificate(subject pkix.Name, dnsNames []string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
