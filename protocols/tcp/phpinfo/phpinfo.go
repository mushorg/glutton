// Package phpinfo emulates a forgotten phpinfo() page on a Debian 11 Apache
// host with mod_php 7.4. Exposure scanners (Censys, nuclei phpinfo-files)
// request well-known paths and record the PHP version and configuration; the
// page matches what they look for ("PHP Version", "PHP Extension", the Core
// version row). Request headers and server variables are reflected like the
// real page, HTML-escaped. The package does no I/O.
package phpinfo

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	mrand "math/rand/v2"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	phpVersion    = "7.4.33"
	serverVersion = "Apache/2.4.62 (Debian)"
	documentRoot  = "/var/www/html"

	maxHeaders     = 64
	maxHeaderValue = 1024
	maxParams      = 32

	httpDate = "Mon, 02 Jan 2006 15:04:05 GMT"
)

//go:embed phpinfo.html.tmpl
var templates embed.FS

var page = template.Must(template.ParseFS(templates, "phpinfo.html.tmpl"))

// Request tags a read frame that asked for a phpinfo page.
type Request struct {
	Page string `json:"page"` // script name the client asked for, e.g. phpinfo.php
}

// Identity is the per-process host persona: random per sensor so sensors do
// not share a hostname or kernel build, replaceable in tests.
type Identity struct {
	Hostname string
	Kernel   string // uname -r
	Build    string // uname -v
	// InvocationID is systemd's apache2.service invocation, in the environment
	InvocationID string
}

// Server is the identity used by Respond.
var Server = NewIdentity()

// NewIdentity returns a random Debian 11 web host identity.
func NewIdentity() Identity {
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	invocation := make([]byte, 16)
	_, _ = rand.Read(invocation)
	kernels := []struct{ release, build string }{
		{"5.10.0-28-amd64", "#1 SMP Debian 5.10.209-2 (2024-01-31)"},
		{"5.10.0-30-amd64", "#1 SMP Debian 5.10.218-1 (2024-06-01)"},
		{"5.10.0-32-amd64", "#1 SMP Debian 5.10.223-1 (2024-08-10)"},
		{"5.10.0-33-amd64", "#1 SMP Debian 5.10.226-1 (2024-10-03)"},
	}
	k := kernels[mrand.IntN(len(kernels))] // #nosec G404 -- persona, not a secret
	names := []string{"web01", "web1", "www", "www1", "srv01", "vps", "debian", "lamp"}
	host := names[mrand.IntN(len(names))] // #nosec G404 -- persona, not a secret
	if strings.HasPrefix(host, "vps") || host == "debian" {
		host += "-" + hex.EncodeToString(suffix)
	}
	return Identity{Hostname: host, Kernel: k.release, Build: k.build, InvocationID: hex.EncodeToString(invocation)}
}

// rootOnly are generic test-script names: a phpinfo page only at the web
// root, where people drop them. Other names match in any directory.
var (
	rootOnly = map[string]bool{
		"i.php": true, "pi.php": true, "p.php": true, "php.php": true, "php2.php": true,
		"test.php": true, "a.php": true, "asdf.php": true, "time.php": true, "temp.php": true,
		"testxx.php": true,
	}
	anyDir = map[string]bool{
		"phpinfo.php": true, "info.php": true, "infophp.php": true, "php_info.php": true,
		"php-info.php": true, "pinfo.php": true, "phpversion.php": true, "inf0.php": true,
		"infos.php": true, "old_phpinfo.php": true, "phpinfo": true, "linusadmin-phpinfo.php": true,
	}
)

// Match returns the tag for a request that asks for a phpinfo page: the
// well-known script names (as nuclei phpinfo-files and Censys probe them),
// /?phpinfo=1 and /l.php?act=phpinfo. path is the escaped request path.
func Match(escapedPath, rawQuery string) *Request {
	p := strings.ToLower(escapedPath)
	if p == "" || strings.Contains(p, "%") {
		return nil
	}
	clean := path.Clean(p)
	base := path.Base(clean)
	switch {
	case anyDir[base]:
	case rootOnly[base] && path.Dir(clean) == "/":
	case (clean == "/" || base == "index.php") && hasQuery(rawQuery, "phpinfo", ""):
		base = "index.php"
	case base == "l.php" && hasQuery(rawQuery, "act", "phpinfo"):
	default:
		return nil
	}
	return &Request{Page: base}
}

func hasQuery(rawQuery, key, value string) bool {
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, key) && (value == "" || strings.EqualFold(v, value)) {
			return true
		}
	}
	return false
}

// Input is what Respond needs to know about the request and connection.
type Input struct {
	Method     string
	RequestURI string
	Path       string // unescaped path
	RawQuery   string
	Proto      string
	RawRequest []byte // header order is taken from the raw bytes
	RemoteAddr string
	RemotePort string
	ServerAddr string
	ServerPort uint16
	HTTPS      bool
	Now        time.Time
}

type row struct {
	Key, Value string
}

type view struct {
	Version, Server, System, Hostname, InvocationID, RequestLine string
	Port                                                         uint16
	Headers, Apache, Vars                                        []row
}

// Respond returns the full HTTP response for a phpinfo page.
func Respond(in Input) []byte {
	headers := headerLines(in.RawRequest)
	host := ""
	for _, h := range headers {
		if strings.EqualFold(h.Key, "Host") {
			host = h.Value
			break
		}
	}
	serverName := host
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.HasPrefix(host, "[") {
		serverName = h
	}
	if serverName == "" {
		serverName = in.ServerAddr
	}
	scheme := "http"
	if in.HTTPS {
		scheme = "https"
	}
	script := in.Path
	if script == "" || strings.HasSuffix(script, "/") {
		script = path.Join(script, "index.php")
	}
	port := strconv.Itoa(int(in.ServerPort))

	var env []row
	if in.HTTPS {
		env = append(env, row{"HTTPS", "on"})
	}
	for _, h := range headers {
		switch strings.ToLower(h.Key) {
		case "content-type":
			env = append(env, row{"CONTENT_TYPE", h.Value})
		case "content-length":
			env = append(env, row{"CONTENT_LENGTH", h.Value})
		case "authorization", "proxy-authorization":
			// Apache hides these from the environment
		default:
			env = append(env, row{"HTTP_" + strings.ToUpper(strings.ReplaceAll(h.Key, "-", "_")), h.Value})
		}
	}
	env = append(env,
		row{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		row{"SERVER_SIGNATURE", fmt.Sprintf("<address>%s Server at %s Port %s</address>\n", serverVersion, serverName, port)},
		row{"SERVER_SOFTWARE", serverVersion},
		row{"SERVER_NAME", serverName},
		row{"SERVER_ADDR", in.ServerAddr},
		row{"SERVER_PORT", port},
		row{"REMOTE_ADDR", in.RemoteAddr},
		row{"DOCUMENT_ROOT", documentRoot},
		row{"REQUEST_SCHEME", scheme},
		row{"CONTEXT_PREFIX", ""},
		row{"CONTEXT_DOCUMENT_ROOT", documentRoot},
		row{"SERVER_ADMIN", "webmaster@localhost"},
		row{"SCRIPT_FILENAME", documentRoot + script},
		row{"REMOTE_PORT", in.RemotePort},
		row{"GATEWAY_INTERFACE", "CGI/1.1"},
		row{"SERVER_PROTOCOL", in.Proto},
		row{"REQUEST_METHOD", in.Method},
		row{"QUERY_STRING", in.RawQuery},
		row{"REQUEST_URI", in.RequestURI},
		row{"SCRIPT_NAME", script},
	)

	vars := make([]row, 0, len(env)+8)
	for _, e := range env {
		vars = append(vars, row{"$_SERVER['" + e.Key + "']", e.Value})
	}
	vars = append(vars,
		row{"$_SERVER['PHP_SELF']", script},
		row{"$_SERVER['REQUEST_TIME_FLOAT']", strconv.FormatFloat(float64(in.Now.UnixMicro())/1e6, 'f', 3, 64)},
		row{"$_SERVER['REQUEST_TIME']", strconv.FormatInt(in.Now.Unix(), 10)},
	)
	for i, kv := range strings.Split(in.RawQuery, "&") {
		if kv == "" || i >= maxParams {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		vars = append(vars, row{"$_GET['" + clip(k) + "']", clip(v)})
	}

	id := Server
	var body bytes.Buffer
	_ = page.Execute(&body, view{
		Version:      phpVersion,
		Server:       serverVersion,
		System:       fmt.Sprintf("Linux %s %s %s x86_64", id.Hostname, id.Kernel, id.Build),
		Hostname:     id.Hostname,
		InvocationID: id.InvocationID,
		RequestLine:  in.Method + " " + in.RequestURI + " " + in.Proto,
		Port:         in.ServerPort,
		Headers:      headers,
		Apache:       env,
		Vars:         vars,
	})
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nDate: %s\r\nServer: %s\r\nVary: Accept-Encoding\r\nContent-Length: %d\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		in.Now.UTC().Format(httpDate), serverVersion, body.Len())
	if in.Method == "HEAD" {
		return []byte(head)
	}
	return append([]byte(head), body.Bytes()...)
}

// headerLines returns the request's header fields in wire order, capped in
// count and value length.
func headerLines(raw []byte) []row {
	head, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	var out []row
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			continue
		}
		out = append(out, row{k, clip(strings.TrimSpace(v))})
		if len(out) == maxHeaders {
			break
		}
	}
	return out
}

func clip(s string) string {
	if len(s) > maxHeaderValue {
		return s[:maxHeaderValue]
	}
	return s
}
