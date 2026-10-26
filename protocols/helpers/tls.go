package helpers

import (
	"container/list"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
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
		e.cert, e.err = generateCertificate(subject, dnsNames, nil)
	})
	return e.cert, e.err
}

// SelfSignedCertificateForHost returns a self-signed certificate whose CN and
// SAN match host (DNS name or IP). Empty, oversized, or invalid hosts fall
// back to CN=localhost. The host is attacker chosen (tunnel SNI or CONNECT
// target), so every host certificate is signed with one shared key (an RSA
// key costs ~40ms of CPU to generate, a signature ~1ms) and only the
// hostCertMax most recently used certificates are kept.
func SelfSignedCertificateForHost(host string) (tls.Certificate, error) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsRune(host, 0) {
		return SelfSignedCertificate(pkix.Name{CommonName: "localhost"}, "localhost")
	}
	ip := net.ParseIP(host)
	key := "dns:" + host
	if ip != nil {
		key = "ip:" + ip.String()
	}
	e := hostCertEntry(key)
	e.once.Do(func() {
		var priv *rsa.PrivateKey
		if priv, e.err = sharedHostKey(); e.err != nil {
			return
		}
		if ip != nil {
			e.cert, e.err = signCertificate(priv, pkix.Name{CommonName: ip.String()}, nil, []net.IP{ip})
		} else {
			e.cert, e.err = signCertificate(priv, pkix.Name{CommonName: host}, []string{host}, nil)
		}
	})
	return e.cert, e.err
}

// hostCertMax bounds the per-host certificates kept; a var so tests can
// shrink it.
var hostCertMax = 4096

type hostCertItem struct {
	key string
	certEntry
}

var hostCerts = struct {
	sync.Mutex
	index map[string]*list.Element
	order *list.List // front = most recently used
}{index: map[string]*list.Element{}, order: list.New()}

// hostCertEntry returns the cache entry for key, creating it and dropping the
// least recently used one when full.
func hostCertEntry(key string) *hostCertItem {
	hostCerts.Lock()
	defer hostCerts.Unlock()
	if el, ok := hostCerts.index[key]; ok {
		hostCerts.order.MoveToFront(el)
		return el.Value.(*hostCertItem)
	}
	for hostCerts.order.Len() >= hostCertMax {
		oldest := hostCerts.order.Back()
		delete(hostCerts.index, oldest.Value.(*hostCertItem).key)
		hostCerts.order.Remove(oldest)
	}
	e := &hostCertItem{key: key}
	hostCerts.index[key] = hostCerts.order.PushFront(e)
	return e
}

var hostKey struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

// sharedHostKey returns the RSA key all host certificates share, generated
// once per process.
func sharedHostKey() (*rsa.PrivateKey, error) {
	hostKey.once.Do(func() {
		hostKey.key, hostKey.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	return hostKey.key, hostKey.err
}

func generateCertificate(subject pkix.Name, dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	return signCertificate(key, subject, dnsNames, ips)
}

// signCertificate creates a self-signed server certificate for key.
func signCertificate(key *rsa.PrivateKey, subject pkix.Name, dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
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
