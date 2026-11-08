package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

// The shared certificate served by TerminateTLS used to be CN=localhost on
// every sensor, which let certificate-indexing scanners (Censys, Shodan) tie
// sensors together. It now looks like a distribution "snakeoil" certificate
// (make-ssl-cert): CN and SAN are the host name, valid for ten years from a
// date in the past. The name is per sensor and survives restarts.

// sensorCertFile is the file in var-dir holding the generated name.
const sensorCertFile = "tls_cert_name"

var sensorNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var (
	sensorNameOnce sync.Once
	sensorName     string

	sensorCertsOnce sync.Once
	sensorCerts     []tls.Certificate
	sensorCertsErr  error

	// sensorNow and sensorRand are swapped by tests.
	sensorNow            = time.Now
	sensorRand io.Reader = rand.Reader
)

// SensorCertName returns the host name used as CN and SAN of the shared
// self-signed certificate. It is read from the tls.cert_name key; when that is
// unset or not a valid host label, a cloud-style host name is generated once
// and persisted in <var-dir>/tls_cert_name. Without a writable var-dir it is
// random per process.
func SensorCertName() string {
	sensorNameOnce.Do(func() {
		if name := strings.ToLower(strings.TrimSpace(viper.GetString("tls.cert_name"))); sensorNameRE.MatchString(name) {
			sensorName = name
			return
		}
		sensorName = persistedSensorName(viper.GetString("var-dir"))
	})
	return sensorName
}

// persistedSensorName loads the generated name from dir, creating and saving a
// new one on first use. An empty dir skips persistence.
func persistedSensorName(dir string) string {
	if dir == "" {
		return randomSensorName()
	}
	path := filepath.Join(dir, sensorCertFile)
	if b, err := os.ReadFile(path); err == nil {
		if name := strings.TrimSpace(string(b)); sensorNameRE.MatchString(name) {
			return name
		}
	}
	name := randomSensorName()
	if err := os.MkdirAll(dir, 0o755); err == nil {
		_ = os.WriteFile(path, []byte(name), 0o644)
	}
	return name
}

// randInt returns a uniform value in [0, n).
func randInt(n int64) int64 {
	v, err := rand.Int(sensorRand, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return v.Int64()
}

// randomSensorName returns a host name in one of the shapes cloud images
// default to.
func randomSensorName() string {
	const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	suffix := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alnum[randInt(int64(len(alnum)))]
		}
		return string(b)
	}
	switch randInt(4) {
	case 0: // AWS EC2 default
		return fmt.Sprintf("ip-172-31-%d-%d", randInt(256), 1+randInt(254))
	case 1: // Debian/Ubuntu VPS images
		return fmt.Sprintf("vps-%s", suffix(8))
	case 2: // hosting provider numbering
		return fmt.Sprintf("srv%d", 100000+randInt(900000))
	default: // GCE-style instance names
		return fmt.Sprintf("instance-%d-%s", 1+randInt(9), suffix(4))
	}
}

// sensorCertificates returns the shared RSA and ECDSA P-256 certificates, in
// that order, generated once per process for SensorCertName. Both have the
// same validity: ten years starting 30 to 730 days ago.
func sensorCertificates() ([]tls.Certificate, error) {
	sensorCertsOnce.Do(func() {
		name := SensorCertName()
		subject := pkix.Name{CommonName: name}
		notBefore := sensorNow().Add(-time.Duration(30+randInt(700))*24*time.Hour - time.Duration(randInt(86400))*time.Second).Truncate(time.Second)
		notAfter := notBefore.AddDate(10, 0, 0)

		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			sensorCertsErr = err
			return
		}
		rsaCert, err := signCertificateValid(rsaKey, subject, []string{name}, nil, notBefore, notAfter)
		if err != nil {
			sensorCertsErr = err
			return
		}
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			sensorCertsErr = err
			return
		}
		ecCert, err := signCertificateValid(ecKey, subject, []string{name}, nil, notBefore, notAfter)
		if err != nil {
			sensorCertsErr = err
			return
		}
		sensorCerts = []tls.Certificate{rsaCert, ecCert}
	})
	return sensorCerts, sensorCertsErr
}

// resetSensorIdentity drops the cached name and certificates (tests only).
func resetSensorIdentity() {
	sensorNameOnce = sync.Once{}
	sensorName = ""
	sensorCertsOnce = sync.Once{}
	sensorCerts = nil
	sensorCertsErr = nil
}
