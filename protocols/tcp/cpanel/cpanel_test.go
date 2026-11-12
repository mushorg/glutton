package cpanel

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 11, 12, 20, 29, 15, 0, time.UTC)

func parseResponse(t *testing.T, raw []byte, method string) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: method})
	require.NoError(t, err)
	var body bytes.Buffer
	_, err = body.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp, body.String()
}

func TestForPort(t *testing.T) {
	for port, name := range map[uint16]string{2082: "cPanel", 2083: "cPanel", 2086: "WHM", 2087: "WHM", 2095: "Webmail", 2096: "Webmail"} {
		svc, ok := ForPort(port)
		require.True(t, ok, port)
		require.Equal(t, name, svc.Name)
	}
	_, ok := ForPort(8080)
	require.False(t, ok)
}

func TestRespond(t *testing.T) {
	cp, _ := ForPort(2083)
	tests := []struct {
		method, path, query string
		status              int
		contains            string
	}{
		{"GET", "/", "", 200, "<title>cPanel Login</title>"},
		{"GET", "/login/", "", 200, `id="login_form" action="/login/"`},
		{"POST", "/login/", "", 401, "The login is invalid."},
		{"POST", "/login/", "login_only=1", 401, `"message":"invalid_login"`},
		{"GET", "/json-api/listaccts", "api.version=1", 401, "<title>cPanel Login</title>"},
		{"GET", "/execute/Mysql/list_databases", "", 401, "login_form"},
		{"GET", "/cpsess1234567890/frontend/jupiter/index.html", "", 401, "login_form"},
		{"GET", "/scripts2/listaccts", "", 401, "login_form"},
		{"GET", "/.env", "", 404, "Not Found"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path+"?"+tt.query, func(t *testing.T) {
			resp, body := parseResponse(t, Respond(cp, tt.method, tt.path, tt.query, testNow), tt.method)
			require.Equal(t, tt.status, resp.StatusCode)
			require.Contains(t, body, tt.contains)
			require.Equal(t, int64(len(body)), resp.ContentLength)
			require.Equal(t, "cpsrvd", resp.Header.Get("Server"))
			require.Equal(t, "Thu, 12 Nov 2026 20:29:15 GMT", resp.Header.Get("Date"))
			require.NotContains(t, strings.ToLower(body), "glutton")
			require.NotContains(t, strings.ToLower(body), "honeypot")
		})
	}
}

func TestRespondServiceTitle(t *testing.T) {
	whm, _ := ForPort(2087)
	_, body := parseResponse(t, Respond(whm, "GET", "/", "", testNow), "GET")
	require.Contains(t, body, "<title>WHM Login</title>")
	mail, _ := ForPort(2096)
	_, body = parseResponse(t, Respond(mail, "GET", "/", "", testNow), "GET")
	require.Contains(t, body, "<title>Webmail Login</title>")
}

func TestRespondHead(t *testing.T) {
	cp, _ := ForPort(2083)
	raw := Respond(cp, "HEAD", "/", "", testNow)
	_, after, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	require.True(t, ok)
	require.Empty(t, after)
	get, _ := parseResponse(t, Respond(cp, "GET", "/", "", testNow), "GET")
	require.Contains(t, string(raw), "Content-Length: "+get.Header.Get("Content-Length"))
}

func TestCredentials(t *testing.T) {
	long := strings.Repeat("a", 300)
	tests := []struct {
		name, method, path, auth, body, user, pass string
		ok                                         bool
	}{
		{"login form", "POST", "/login/", "", "user=root&pass=hunter2&goto_uri=%2F", "root", "hunter2", true},
		{"login no slash", "POST", "/login", "", "user=admin&pass=p%26ss", "admin", "p&ss", true},
		{"login no pass", "POST", "/login/", "", "user=root", "root", "", true},
		{"login no user", "POST", "/login/", "", "pass=x", "", "", false},
		{"login GET", "GET", "/login/", "", "user=root&pass=x", "", "", false},
		{"bad form", "POST", "/login/", "", "user=%zz", "", "", false},
		{"whm token", "GET", "/json-api/version", "whm root:ABCDEF0123", "", "root", "ABCDEF0123", true},
		{"cpanel token", "GET", "/execute/Email/list_pops", "cpanel bob:TOKEN", "", "bob", "TOKEN", true},
		{"token no colon", "GET", "/json-api/version", "whm root", "", "", "", false},
		{"basic left to caller", "GET", "/json-api/version", "Basic cm9vdDp4", "", "", "", false},
		{"capped", "POST", "/login/", "", "user=" + long + "&pass=" + long, long[:maxField], long[:maxField], true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.auth != "" {
				h.Set("Authorization", tt.auth)
			}
			user, pass, ok := Credentials(tt.method, tt.path, h, []byte(tt.body))
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.user, user)
			require.Equal(t, tt.pass, pass)
		})
	}
}
