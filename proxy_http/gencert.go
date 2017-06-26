// Copyright (c) 2012-today José Carlos Nieto, https://menteslibres.net/xiam
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package gencert generates SSL certificates for any host on the fly.
package proxy_http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

const (
	certDirectory = "certs"
	rsaBits       = 2048
	pathSeparator = string(os.PathSeparator)
)

var (
	rootCACert = "../../ssl/rootCA.crt"
	rootCAKey  = "../../ssl/rootCA.key"
)

var (
	mu sync.Mutex
)

// setRootCACert sets the root CA cert.
func (p *Proxy) setRootCACert(s string) {
	rootCACert = s
}

// setRootCAKey sets the root CA key.
func (p *Proxy) setRootCAKey(s string) {
	rootCAKey = s
}

// createKeyPair creates a key pair for the given hostname on the fly.
func (p *Proxy) createKeyPair(commonName string) (certFile string, keyFile string, err error) {
	mu.Lock()
	defer mu.Unlock()

	commonName, err = idna.ToASCII(commonName)
	if err != nil {
		return
	}

	commonName = strings.ToLower(commonName)

	destDir := certDirectory + pathSeparator + commonName + pathSeparator

	certFile = destDir + "cert.pem"
	keyFile = destDir + "key.pem"

	// Attempt to verify certs.
	if _, err = tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		// Keys already in place
		return
	}

	p.logger.Info(fmt.Sprintf("[http.prxy] Creating SSL certificate for %s...", commonName))

	notBefore := time.Now().Add(-24 * 30 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Glutton Certificates, Inc"},
			CommonName:   commonName,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, commonName)
	}

	rootCA, err := tls.LoadX509KeyPair(rootCACert, rootCAKey)
	if err != nil {
		return
	}

	if rootCA.Leaf, err = x509.ParseCertificate(rootCA.Certificate[0]); err != nil {
		return
	}

	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, rsaBits); err != nil {
		return
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, rootCA.Leaf, &priv.PublicKey, rootCA.PrivateKey); err != nil {
		return
	}

	if err = os.MkdirAll(destDir, 0755); err != nil {
		return
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return
}
