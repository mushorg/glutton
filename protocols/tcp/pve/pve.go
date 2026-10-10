// Package pve emulates the unauthenticated HTTPS surface of a Proxmox VE node
// (pveproxy on tcp/8006): the web UI login page, failed API logins, and the
// node's cluster-CA-signed certificate. No login ever succeeds. The package
// does no I/O.
package pve

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

const (
	// Port is the pveproxy port; every path there is the PVE persona.
	Port = 8006

	managerVersion = "8.2.4"
	toolkitVersion = "4.2.3"
	extVersion     = "7.0.0"
	serverHeader   = "pve-api-daemon/3.0"

	ticketPath  = "/api2/json/access/ticket"
	maxUsername = 256
)

// Identity is the per-process node persona: random per sensor (or set with
// pve.node_name / pve.domain) so sensors do not share a hostname or CA.
type Identity struct {
	Node   string
	Domain string
	CAUnit string // cluster CA OU, a UUID per cluster
}

var (
	identityOnce sync.Once
	identity     Identity

	certOnce sync.Once
	cert     tls.Certificate
	certErr  error
)

// Node returns the stable node identity.
func Node() Identity {
	identityOnce.Do(func() {
		identity = Identity{
			Node:   viper.GetString("pve.node_name"),
			Domain: viper.GetString("pve.domain"),
			CAUnit: uuid.NewString(),
		}
		if identity.Node == "" {
			identity.Node = pick([]string{"pve", "pve1", "pve01", "pve-01", "proxmox", "pmx1", "node1", "hv01"})
		}
		if identity.Domain == "" {
			identity.Domain = pick([]string{"local", "localdomain", "lan", "home.arpa", "internal"})
		}
	})
	return identity
}

func pick(names []string) string {
	return names[mrand.IntN(len(names))] // #nosec G404 -- persona, not a secret
}

// Certificate returns the node certificate pveproxy serves: a leaf for
// <node>.<domain> (OU=PVE Cluster Node) signed by a per-cluster
// "Proxmox Virtual Environment" CA. It is generated once per process.
func Certificate() (tls.Certificate, error) {
	certOnce.Do(func() {
		cert, certErr = generateCertificate(Node(), time.Now())
	})
	return cert, certErr
}

func generateCertificate(id Identity, now time.Time) (tls.Certificate, error) {
	// the node was installed some time ago, not when the sensor started
	installed := now.Add(-time.Duration(30+mrand.IntN(400)) * 24 * time.Hour).Truncate(time.Second) // #nosec G404
	fqdn := id.Node + "." + id.Domain

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:         "Proxmox Virtual Environment",
			OrganizationalUnit: []string{id.CAUnit},
			Organization:       []string{"PVE Cluster Manager CA"},
		},
		NotBefore:             installed,
		NotAfter:              installed.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:         fqdn,
			OrganizationalUnit: []string{"PVE Cluster Node"},
			Organization:       []string{"Proxmox Virtual Environment"},
		},
		DNSNames:              []string{"localhost", id.Node, fqdn},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             installed,
		NotAfter:              installed.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	// pveproxy serves the node certificate only, not the CA
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

// LoginUsername returns the username of a ticket (login) request. The
// password is never returned.
func LoginUsername(method, path string, body []byte) (string, bool) {
	if method != http.MethodPost || path != ticketPath {
		return "", false
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false
	}
	user := form.Get("username")
	if user == "" {
		return "", false
	}
	if realm := form.Get("realm"); realm != "" && !strings.Contains(user, "@") {
		user += "@" + realm
	}
	if len(user) > maxUsername {
		user = user[:maxUsername]
	}
	return user, true
}

// Respond builds the pveproxy reply for a request. now sets Date/Expires.
func Respond(method, path string, now time.Time) []byte {
	switch {
	case path == "/" && (method == http.MethodGet || method == http.MethodHead):
		body := indexPage(Node().Node)
		if method == http.MethodHead {
			return response("200 OK", "text/html; charset=utf-8", len(body), nil, now)
		}
		return response("200 OK", "text/html; charset=utf-8", len(body), body, now)
	case path == ticketPath && method == http.MethodPost:
		body := []byte(`{"data":null}`)
		return response("401 authentication failure", "application/json;charset=UTF-8", len(body), body, now)
	case strings.HasPrefix(path, "/api2/"):
		return response("401 No ticket", "", 0, nil, now)
	}
	return response("404 Not Found", "", 0, nil, now)
}

func response(status, contentType string, length int, body []byte, now time.Time) []byte {
	date := now.UTC().Format(http.TimeFormat)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	b.WriteString("Cache-Control: max-age=0\r\n")
	b.WriteString("Connection: Keep-Alive\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", date)
	b.WriteString("Pragma: no-cache\r\n")
	fmt.Fprintf(&b, "Server: %s\r\n", serverHeader)
	fmt.Fprintf(&b, "Content-Length: %d\r\n", length)
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&b, "Expires: %s\r\n\r\n", date)
	return append([]byte(b.String()), body...)
}

func indexPage(node string) []byte {
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title>%[1]s - Proxmox Virtual Environment</title>
    <link rel="icon" sizes="128x128" href="/pve2/images/logo-128.png" />
    <link rel="apple-touch-icon" sizes="128x128" href="/pve2/images/logo-128.png" />
    <link rel="stylesheet" type="text/css" href="/pve2/ext6/theme-crisp/resources/theme-crisp-all.css?ver=%[3]s" />
    <link rel="stylesheet" type="text/css" href="/pve2/ext6/crisp/resources/charts-all.css?ver=%[3]s" />
    <link rel="stylesheet" type="text/css" href="/pve2/fa/css/font-awesome.css" />
    <link rel="stylesheet" type="text/css" href="/pve2/css/ext6-pve.css?ver=%[2]s" />
    <link rel="stylesheet" type="text/css" href="/pwt/css/ext6-pmx.css?ver=%[4]s" />
    <script type='text/javascript'> function gettext(buf) { return buf; } </script>
    <script type="text/javascript" src="/pve2/ext6/ext-all.js?ver=%[3]s"></script>
    <script type="text/javascript" src="/pve2/ext6/charts.js?ver=%[3]s"></script>
    <script type="text/javascript" src="/pve2/js/u2f-api.js"></script>
    <script type="text/javascript" src="/qrcode.min.js"></script>
    <script type="text/javascript">
    Proxmox = {
	Setup: { auth_cookie_name: 'PVEAuthCookie' },
	defaultLang: 'en',
	NodeName: '%[1]s',
	UserName: '',
	CSRFPreventionToken: null,
	ConsentText: '',
    };
    </script>
    <script type="text/javascript" src="/proxmoxlib.js?ver=%[4]s"></script>
    <script type="text/javascript" src="/pve2/js/pvemanagerlib.js?ver=%[2]s"></script>
    <script type="text/javascript" src="/pve2/ext6/locale/locale-en.js?ver=%[3]s"></script>
    <script type="text/javascript">
    if (typeof(PVE) === 'undefined') PVE = {};
    PVE.UserName = '';
    PVE.CSRFPreventionToken = null;
    </script>
    <script type="text/javascript">
      Ext.History.fieldid = 'x-history-field';
      Ext.onReady(function() { Ext.create('PVE.StdWorkspace');});
    </script>
  </head>
  <body>
    <!-- Fields required for history management -->
    <form id="history-form" class="x-hidden">
    <input type="hidden" id="x-history-field"/>
    </form>
  </body>
</html>
`, node, managerVersion, extVersion, toolkitVersion))
}
