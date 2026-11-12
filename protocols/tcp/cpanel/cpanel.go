// Package cpanel emulates the unauthenticated surface of cPanel & WHM's
// cpsrvd daemon: the cPanel (2082/2083), WHM (2086/2087) and Webmail
// (2095/2096) login pages, failed logins and API calls without a session.
// No login ever succeeds. The package does no I/O.
//
// Response shapes follow cPanel's login template docs (form id login_form,
// POST /login/, fields user/pass) and the WhatWeb cPanel plugin (Server
// header cpsrvd). The exact header set and JSON bodies are approximations.
package cpanel

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	serverHeader = "cpsrvd"
	maxField     = 256
	loginPath    = "/login/"
)

// Service is the cpsrvd application behind a port.
type Service struct {
	Name  string // cPanel, WHM or Webmail
	Port  uint16
	HTTPS bool
}

var services = map[uint16]Service{
	2082: {"cPanel", 2082, false},
	2083: {"cPanel", 2083, true},
	2086: {"WHM", 2086, false},
	2087: {"WHM", 2087, true},
	2095: {"Webmail", 2095, false},
	2096: {"Webmail", 2096, true},
}

// ForPort returns the cpsrvd service listening on port, if any.
func ForPort(port uint16) (Service, bool) {
	s, ok := services[port]
	return s, ok
}

// Credentials returns the username and password a request carries: the
// login form (POST /login/, fields user/pass) or a cPanel/WHM API token
// header ("Authorization: cpanel user:token" / "whm user:token"). Both are
// capped at 256 bytes. HTTP Basic is left to the caller.
func Credentials(method, path string, header http.Header, body []byte) (string, string, bool) {
	if method == http.MethodPost && isLoginPath(path) {
		form, err := url.ParseQuery(string(body))
		if err == nil && form.Has("user") {
			return capField(form.Get("user")), capField(form.Get("pass")), true
		}
	}
	scheme, cred, ok := strings.Cut(strings.TrimSpace(header.Get("Authorization")), " ")
	if !ok {
		return "", "", false
	}
	switch strings.ToLower(scheme) {
	case "cpanel", "whm":
		user, token, ok := strings.Cut(strings.TrimSpace(cred), ":")
		if !ok || user == "" {
			return "", "", false
		}
		return capField(user), capField(token), true
	}
	return "", "", false
}

func capField(s string) string {
	if len(s) > maxField {
		return s[:maxField]
	}
	return s
}

func isLoginPath(path string) bool {
	return path == "/login" || path == loginPath
}

// isProtected reports whether path needs a cpsrvd session: API endpoints,
// security-token prefixed paths (/cpsess0123456789/...) and the UIs.
func isProtected(path string) bool {
	for _, p := range []string{"/json-api/", "/execute/", "/xml-api/", "/scripts", "/frontend/", "/cpsess", "/3rdparty/", "/webmail/", "/logout"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Respond builds the cpsrvd reply for a request on svc. query is the raw
// query string; now sets the Date header.
func Respond(svc Service, method, path, query string, now time.Time) []byte {
	head := method == http.MethodHead
	switch {
	case path == "/" && (method == http.MethodGet || head):
		return page("200 OK", svc, "", head, now)
	case isLoginPath(path) && method == http.MethodPost:
		if q, err := url.ParseQuery(query); err == nil && q.Get("login_only") == "1" {
			body := []byte(`{"status":0,"redirect":null,"message":"invalid_login","security_token":null}`)
			return response("401 Access Denied", "application/json", body, false, now)
		}
		return page("401 Access Denied", svc, "The login is invalid.", false, now)
	case isLoginPath(path):
		return page("200 OK", svc, "", head, now)
	case isProtected(path):
		return page("401 Access Denied", svc, "", head, now)
	}
	return response("404 Not Found", "text/html; charset=utf-8", notFound, head, now)
}

var notFound = []byte("<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n")

func page(status string, svc Service, message string, head bool, now time.Time) []byte {
	return response(status, "text/html; charset=utf-8", loginPage(svc, message), head, now)
}

func response(status, contentType string, body []byte, head bool, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(http.TimeFormat))
	b.WriteString("Cache-Control: no-cache, no-store, must-revalidate, private\r\n")
	b.WriteString("Pragma: no-cache\r\n")
	fmt.Fprintf(&b, "Server: %s\r\n", serverHeader)
	b.WriteString("X-Frame-Options: SAMEORIGIN\r\n")
	b.WriteString("X-Content-Type-Options: nosniff\r\n\r\n")
	out := []byte(b.String())
	if head {
		return out
	}
	return append(out, body...)
}

func loginPage(svc Service, message string) []byte {
	msg := ""
	if message != "" {
		msg = fmt.Sprintf("\n            <div id=\"login-status\" class=\"error-notice\"><span class=\"login-status-icon\"></span><div id=\"login-status-message\">%s</div></div>", message)
	}
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta name="robots" content="noindex">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="google" content="notranslate">
    <title>%[1]s Login</title>
    <link rel="shortcut icon" href="/unprotected/cpanel/favicon.ico">
    <link rel="stylesheet" href="/unprotected/cpanel/style_v2_optimized.css">
</head>
<body class="cpanel" id="login_page">
    <div id="login-wrapper" class="group">
        <div class="wrapper">
            <div id="login-container" class="group">
                <div id="login-sub-container">
                    <div id="login-sub-header"><img class="main-logo" src="/unprotected/cpanel/images/cpanel-logo.svg" alt="logo"></div>%[2]s
                    <div id="login-sub">
                        <div id="forms">
                            <form novalidate id="login_form" action="/login/" method="post" target="_top">
                                <div class="input-req-login"><label for="user">Username</label></div>
                                <div class="input-field-login icon username-container">
                                    <input name="user" id="user" autofocus="autofocus" value="" placeholder="Enter your username." class="std_textbox" type="text" tabindex="1" required>
                                </div>
                                <div class="input-req-login login-password-field-label"><label for="pass">Password</label></div>
                                <div class="input-field-login icon password-container">
                                    <input name="pass" id="pass" placeholder="Enter your account password." class="std_textbox" type="password" tabindex="2" required>
                                </div>
                                <div class="controls">
                                    <div class="login-btn"><button name="login" type="submit" id="login_submit" tabindex="3">Log in</button></div>
                                </div>
                                <input type="hidden" name="goto_uri" id="goto_uri" value="/">
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <footer><div class="copyright">Copyright&copy; 2026 cPanel, L.L.C.</div></footer>
</body>
</html>
`, svc.Name, msg))
}
