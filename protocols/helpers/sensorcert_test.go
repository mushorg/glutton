package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// withSensorIdentity runs with a fresh sensor identity under var-dir dir and
// tls.cert_name name, restoring the cached identity afterwards.
func withSensorIdentity(t *testing.T, dir, name string) {
	t.Helper()
	prevDir, prevName := viper.GetString("var-dir"), viper.GetString("tls.cert_name")
	viper.Set("var-dir", dir)
	viper.Set("tls.cert_name", name)
	resetSensorIdentity()
	t.Cleanup(func() {
		viper.Set("var-dir", prevDir)
		viper.Set("tls.cert_name", prevName)
		resetSensorIdentity()
	})
}

func TestSensorCertNamePersisted(t *testing.T) {
	dir := t.TempDir()
	withSensorIdentity(t, dir, "")

	name := SensorCertName()
	require.NotEqual(t, "localhost", name)
	require.Regexp(t, sensorNameRE, name)
	b, err := os.ReadFile(filepath.Join(dir, sensorCertFile))
	require.NoError(t, err)
	require.Equal(t, name, string(b))

	// a restart reads the same name back
	resetSensorIdentity()
	require.Equal(t, name, SensorCertName())
}

func TestSensorCertNameOverride(t *testing.T) {
	withSensorIdentity(t, t.TempDir(), "Web01")
	require.Equal(t, "web01", SensorCertName())

	// an invalid override falls back to a generated name
	withSensorIdentity(t, "", "bad name!")
	require.NotEqual(t, "bad name!", SensorCertName())
	require.Regexp(t, sensorNameRE, SensorCertName())
}

func TestRandomSensorNameVaries(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		name := randomSensorName()
		require.Regexp(t, sensorNameRE, name)
		seen[name] = true
	}
	require.Greater(t, len(seen), 1)
}

func TestSensorCertificatesShape(t *testing.T) {
	withSensorIdentity(t, "", "srv123456")
	fixed := time.Date(2026, 11, 8, 17, 55, 0, 0, time.UTC)
	prevNow := sensorNow
	sensorNow = func() time.Time { return fixed }
	t.Cleanup(func() { sensorNow = prevNow })

	certs, err := sensorCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 2)
	rsaLeaf, err := x509.ParseCertificate(certs[0].Certificate[0])
	require.NoError(t, err)
	ecLeaf, err := x509.ParseCertificate(certs[1].Certificate[0])
	require.NoError(t, err)

	require.Equal(t, x509.RSA, rsaLeaf.PublicKeyAlgorithm)
	require.Equal(t, x509.ECDSA, ecLeaf.PublicKeyAlgorithm)
	for _, leaf := range []*x509.Certificate{rsaLeaf, ecLeaf} {
		require.Equal(t, "srv123456", leaf.Subject.CommonName)
		require.Equal(t, []string{"srv123456"}, leaf.DNSNames)
		require.True(t, leaf.NotBefore.Before(fixed.Add(-29*24*time.Hour)), "backdated")
		require.True(t, leaf.NotBefore.After(fixed.Add(-731*24*time.Hour)))
		require.Equal(t, leaf.NotBefore.AddDate(10, 0, 0), leaf.NotAfter)
		require.Greater(t, leaf.SerialNumber.BitLen(), 64, "OpenSSL-sized serial")
	}
	require.Equal(t, rsaLeaf.NotBefore, ecLeaf.NotBefore)
	require.NotEqual(t, rsaLeaf.SerialNumber, ecLeaf.SerialNumber)

	again, err := sensorCertificates()
	require.NoError(t, err)
	require.Equal(t, certs[0].Certificate[0], again[0].Certificate[0], "cached per process")
}

// A client sending an unrelated SNI still gets the sensor certificate.
func TestTerminateTLSServesSensorCert(t *testing.T) {
	withSensorIdentity(t, "", "vps-a1b2c3d4")
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	res := make(chan error, 1)
	go func() {
		_, _, err := TerminateTLS(server)
		res <- err
	}()
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "unknown.example"})
	require.NoError(t, tc.Handshake())
	leaf := tc.ConnectionState().PeerCertificates[0]
	require.Equal(t, "vps-a1b2c3d4", leaf.Subject.CommonName)
	require.NoError(t, <-res)
}
