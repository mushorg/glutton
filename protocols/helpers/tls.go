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

// SelfSignedCertificateRDP returns a self-signed certificate that matches the
// shape of a real Windows RDP certificate: CN = computerName, no SAN, ~6-month
// validity, and KeyUsage keyEncipherment|dataEncipherment with EKU serverAuth.
// The key pair is generated once per process and cached by computerName.
func SelfSignedCertificateRDP(computerName string) (tls.Certificate, error) {
	subject := pkix.Name{CommonName: computerName}
	v, _ := selfSignedCerts.LoadOrStore("rdp:"+subject.String(), &certEntry{})
	e := v.(*certEntry)
	e.once.Do(func() {
		e.cert, e.err = generateRDPCertificate(subject)
	})
	return e.cert, e.err
}

// generateRDPCertificate creates a self-signed cert resembling a Windows RDP
// server certificate: no SAN, ~6-month validity, no BasicConstraints,
// KeyUsage keyEncipherment|dataEncipherment.
func generateRDPCertificate(subject pkix.Name) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		// No DNSNames → no SAN extension, matching real RDP self-signed certs.
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(180 * 24 * time.Hour), // ~6 months
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// No BasicConstraintsValid → no BasicConstraints extension.
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
