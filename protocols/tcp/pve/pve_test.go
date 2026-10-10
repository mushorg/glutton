package pve

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 10, 10, 18, 56, 48, 0, time.UTC)

func parseResponse(t *testing.T, raw []byte, method string) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: method})
	require.NoError(t, err)
	var body bytes.Buffer
	_, err = body.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp, body.String()
}

func TestRespond(t *testing.T) {
	tests := []struct {
		method, path string
		status       int
		statusLine   string
		body         string
	}{
		{"POST", "/api2/json/access/ticket", 401, "401 authentication failure", `{"data":null}`},
		{"GET", "/api2/json/version", 401, "401 No ticket", ""},
		{"GET", "/api2/json/nodes", 401, "401 No ticket", ""},
		{"GET", "/.env", 404, "404 Not Found", ""},
		{"POST", "/", 404, "404 Not Found", ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp, body := parseResponse(t, Respond(tt.method, tt.path, testNow), tt.method)
			require.Equal(t, tt.status, resp.StatusCode)
			require.Equal(t, tt.statusLine, resp.Status)
			require.Equal(t, tt.body, body)
			require.Equal(t, "pve-api-daemon/3.0", resp.Header.Get("Server"))
			require.Equal(t, "Sat, 10 Oct 2026 18:56:48 GMT", resp.Header.Get("Date"))
		})
	}
}

func TestRespondIndex(t *testing.T) {
	resp, body := parseResponse(t, Respond("GET", "/", testNow), "GET")
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Equal(t, int64(len(body)), resp.ContentLength)
	node := Node().Node
	require.Contains(t, body, "<title>"+node+" - Proxmox Virtual Environment</title>")
	require.Contains(t, body, "NodeName: '"+node+"'")
	require.Contains(t, body, "pvemanagerlib.js?ver="+managerVersion)
	require.NotContains(t, strings.ToLower(body), "glutton")
	require.NotContains(t, strings.ToLower(body), "honeypot")

	head := Respond("HEAD", "/", testNow)
	_, after, _ := bytes.Cut(head, []byte("\r\n\r\n"))
	require.Empty(t, after)
	require.Contains(t, string(head), "Content-Length: "+resp.Header.Get("Content-Length"))
}

func TestLoginUsername(t *testing.T) {
	tests := []struct {
		name, method, path, body, user string
		ok                             bool
	}{
		{"realm field", "POST", ticketPath, "username=root&password=x&realm=pam", "root@pam", true},
		{"realm in user", "POST", ticketPath, "username=root%40pam&password=x", "root@pam", true},
		{"realm in both", "POST", ticketPath, "username=admin%40pve&password=x&realm=pam", "admin@pve", true},
		{"no username", "POST", ticketPath, "password=x", "", false},
		{"wrong path", "POST", "/api2/json/version", "username=root", "", false},
		{"GET", "GET", ticketPath, "username=root", "", false},
		{"bad form", "POST", ticketPath, "username=%zz", "", false},
		{"capped", "POST", ticketPath, "username=" + strings.Repeat("a", 300), strings.Repeat("a", maxUsername), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, ok := LoginUsername(tt.method, tt.path, []byte(tt.body))
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.user, user)
			require.NotContains(t, user, "x&")
		})
	}
}

func TestCertificate(t *testing.T) {
	id := Identity{Node: "pve1", Domain: "lan", CAUnit: "3f7c2b1e-0000-4000-8000-000000000000"}
	cert, err := generateCertificate(id, testNow)
	require.NoError(t, err)
	require.Len(t, cert.Certificate, 1, "pveproxy serves the node certificate only")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	require.Equal(t, "pve1.lan", leaf.Subject.CommonName)
	require.Equal(t, []string{"PVE Cluster Node"}, leaf.Subject.OrganizationalUnit)
	require.Equal(t, []string{"Proxmox Virtual Environment"}, leaf.Subject.Organization)
	require.Equal(t, "Proxmox Virtual Environment", leaf.Issuer.CommonName)
	require.Equal(t, []string{"PVE Cluster Manager CA"}, leaf.Issuer.Organization)
	require.Equal(t, []string{id.CAUnit}, leaf.Issuer.OrganizationalUnit)
	require.Equal(t, []string{"localhost", "pve1", "pve1.lan"}, leaf.DNSNames)
	require.False(t, leaf.IsCA)
	require.True(t, leaf.NotBefore.Before(testNow.Add(-29*24*time.Hour)), "issued at install time, not at startup")
	require.Equal(t, leaf.NotBefore.AddDate(2, 0, 0), leaf.NotAfter)
}
