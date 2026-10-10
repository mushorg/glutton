// Package selenium emulates the HTTP surface of an unauthenticated Selenium
// Grid 4 standalone hub with one Chrome slot, so attackers abusing exposed
// Grids (SeleniumGreed: a new-session request whose browser binary is python
// or a shell) reveal their payload. No session is ever created: a new-session
// request fails the way a Grid does when the "browser" process exits. The
// package does no I/O.
package selenium

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	// GridPort is the default Grid hub port; every path there is the Grid.
	GridPort = 4444

	version       = "4.45.0"
	revision      = "cd6a3cdfca"
	chromeBinary  = "/usr/bin/google-chrome"
	maxArgs       = 64
	maxArgLen     = 4096
	maxBinaryLen  = 1024
	maxEchoLength = 256
)

// Identity is the per-process persona: random per sensor so sensors do not
// share node IDs, replaceable in tests.
type Identity struct {
	NodeID string
	SlotID string
	Host   string // container hostname
	IP     string
}

// Grid is the identity used by Respond.
var Grid = NewIdentity()

// NewIdentity returns a random Docker-style identity.
func NewIdentity() Identity {
	host := make([]byte, 6)
	_, _ = rand.Read(host)
	return Identity{
		NodeID: uuid.NewString(),
		SlotID: uuid.NewString(),
		Host:   hex.EncodeToString(host),
		IP:     "172.17.0.2",
	}
}

// NewSession is what a new-session request asked the Grid to start.
type NewSession struct {
	Browser   string
	Binary    string
	Args      []string
	Truncated bool // an arg, the binary, or the arg list hit a cap
}

// trimHub strips the legacy /wd/hub prefix Grid 4 still serves.
func trimHub(path string) string {
	if p, ok := strings.CutPrefix(path, "/wd/hub"); ok {
		if p == "" {
			return "/"
		}
		return p
	}
	return path
}

// IsGridRequest reports whether the Grid answers this request: everything on
// the Grid port, and /wd/hub paths on any port.
func IsGridRequest(port uint16, path string) bool {
	return port == GridPort || path == "/wd/hub" || strings.HasPrefix(path, "/wd/hub/")
}

// NewSessionRequest parses a W3C (or legacy desiredCapabilities) new-session
// request. ok is false for other requests or bodies that are not JSON.
func NewSessionRequest(method, path string, body []byte) (NewSession, bool) {
	if method != "POST" || strings.TrimSuffix(trimHub(path), "/") != "/session" {
		return NewSession{}, false
	}
	var req struct {
		Capabilities struct {
			AlwaysMatch map[string]json.RawMessage   `json:"alwaysMatch"`
			FirstMatch  []map[string]json.RawMessage `json:"firstMatch"`
		} `json:"capabilities"`
		Desired map[string]json.RawMessage `json:"desiredCapabilities"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return NewSession{}, false
	}
	// later sources win: legacy, then the first firstMatch, then alwaysMatch
	caps := map[string]json.RawMessage{}
	sources := []map[string]json.RawMessage{req.Desired}
	if len(req.Capabilities.FirstMatch) > 0 {
		sources = append(sources, req.Capabilities.FirstMatch[0])
	}
	sources = append(sources, req.Capabilities.AlwaysMatch)
	for _, src := range sources {
		for k, v := range src {
			caps[k] = v
		}
	}

	var s NewSession
	_ = json.Unmarshal(caps["browserName"], &s.Browser)
	for _, key := range []string{"goog:chromeOptions", "moz:firefoxOptions", "ms:edgeOptions", "chromeOptions"} {
		raw, ok := caps[key]
		if !ok {
			continue
		}
		var opts struct {
			Binary string   `json:"binary"`
			Args   []string `json:"args"`
		}
		if json.Unmarshal(raw, &opts) != nil {
			continue
		}
		if s.Binary == "" {
			s.Binary = opts.Binary
		}
		s.Args = append(s.Args, opts.Args...)
	}
	s.Binary, s.Truncated = capString(s.Binary, maxBinaryLen, s.Truncated)
	if len(s.Args) > maxArgs {
		s.Args, s.Truncated = s.Args[:maxArgs], true
	}
	for i, a := range s.Args {
		s.Args[i], s.Truncated = capString(a, maxArgLen, s.Truncated)
	}
	return s, true
}

func capString(s string, n int, truncated bool) (string, bool) {
	if len(s) > n {
		return s[:n], true
	}
	return s, truncated
}

// Respond builds the Grid's HTTP response for a request IsGridRequest accepted.
func Respond(method, path string, body []byte) []byte {
	p := trimHub(path)
	switch {
	case method == "GET" && p == "/" && !strings.HasPrefix(path, "/wd/hub"):
		return response("302 Found", "text/plain; charset=utf-8", nil, "Location: /ui/\r\n")
	case method == "GET" && (p == "/ui" || strings.HasPrefix(p, "/ui/")):
		return response("200 OK", "text/html; charset=utf-8", []byte(uiIndex), "")
	case method == "GET" && p == "/status":
		return jsonResponse("200 OK", statusBody())
	case method == "POST" && p == "/graphql":
		return jsonResponse("200 OK", graphqlBody(body))
	case strings.TrimSuffix(p, "/") == "/session":
		if method != "POST" {
			return unknownCommand(method, path)
		}
		return newSessionError(body)
	case strings.HasPrefix(p, "/session/"):
		return invalidSession(p)
	}
	return unknownCommand(method, path)
}

const uiIndex = `<!doctype html><html lang="en"><head><meta charset="utf-8"/>` +
	`<link rel="icon" href="/ui/favicon.svg"/><meta name="viewport" content="width=device-width,initial-scale=1"/>` +
	`<meta name="theme-color" content="#000000"/><meta name="description" content="Selenium Grid"/>` +
	`<title>Selenium Grid</title><script defer="defer" src="/ui/static/js/main.js"></script></head>` +
	`<body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div></body></html>`

func response(status, contentType string, body []byte, extra string) []byte {
	head := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"Cache-Control: no-cache\r\n" + extra +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	return append([]byte(head), body...)
}

func jsonResponse(status string, v any) []byte {
	return response(status, "application/json; charset=utf-8", gridJSON(v), "")
}

// escapedSlash is how Selenium's JsonOutput writes '/', so a Grid URI reads
// "http:" + escapedSlash + escapedSlash + "172.17.0.2:4444".
const escapedSlash = "\\" + "u002f"

// gridJSON pretty-prints like Selenium's JsonOutput. '/' only occurs inside
// JSON strings, so replacing it in the output is safe.
func gridJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return bytes.ReplaceAll(b, []byte("/"), []byte(escapedSlash))
}

type osInfo struct {
	Arch    string `json:"arch"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type slotID struct {
	HostID string `json:"hostId"`
	ID     string `json:"id"`
}

type stereotype struct {
	BrowserName   string `json:"browserName"`
	ChromeOptions struct {
		Binary string `json:"binary"`
	} `json:"goog:chromeOptions"`
	PlatformName string `json:"platformName"`
	NoVncPort    int    `json:"se:noVncPort"`
	VncEnabled   bool   `json:"se:vncEnabled"`
}

type slot struct {
	ID          slotID     `json:"id"`
	LastStarted string     `json:"lastStarted"`
	Session     any        `json:"session"`
	Stereotype  stereotype `json:"stereotype"`
}

type node struct {
	ID              string `json:"id"`
	URI             string `json:"uri"`
	MaxSessions     int    `json:"maxSessions"`
	OSInfo          osInfo `json:"osInfo"`
	HeartbeatPeriod int    `json:"heartbeatPeriod"`
	Availability    string `json:"availability"`
	Version         string `json:"version"`
	Slots           []slot `json:"slots"`
}

func gridURI() string { return "http://" + Grid.IP + ":" + strconv.Itoa(GridPort) }

func statusBody() any {
	st := stereotype{BrowserName: "chrome", PlatformName: "linux", NoVncPort: 7900, VncEnabled: true}
	st.ChromeOptions.Binary = chromeBinary
	n := node{
		ID:              Grid.NodeID,
		URI:             gridURI(),
		MaxSessions:     1,
		OSInfo:          osInfo{Arch: "amd64", Name: "Linux", Version: "6.8.0-45-generic"},
		HeartbeatPeriod: 60000,
		Availability:    "UP",
		Version:         version + " (revision " + revision + ")",
		Slots: []slot{{
			ID:          slotID{HostID: Grid.NodeID, ID: Grid.SlotID},
			LastStarted: "1970-01-01T00:00:00Z",
			Stereotype:  st,
		}},
	}
	return map[string]any{"value": map[string]any{
		"ready":   true,
		"message": "Selenium Grid ready.",
		"nodes":   []node{n},
	}}
}

// graphqlFields are the scalar Grid fields, in Grid's schema order. A query
// gets the ones it names; nested node/session lists are not emulated.
var graphqlFields = []struct {
	name  string
	value func() any
}{
	{"uri", func() any { return gridURI() }},
	{"totalSlots", func() any { return 1 }},
	{"nodeCount", func() any { return 1 }},
	{"maxSession", func() any { return 1 }},
	{"sessionCount", func() any { return 0 }},
	{"sessionQueueSize", func() any { return 0 }},
	{"version", func() any { return version }},
}

var graphqlWord = regexp.MustCompile(`[A-Za-z_]+`)

func graphqlBody(body []byte) any {
	var req struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(body, &req)
	words := map[string]bool{}
	for _, w := range graphqlWord.FindAllString(req.Query, -1) {
		words[w] = true
	}
	if !words["grid"] {
		return map[string]any{"errors": []map[string]string{{"message": "Validation error: query must select grid"}}}
	}
	grid := map[string]any{}
	for _, f := range graphqlFields {
		if words[f.name] {
			grid[f.name] = f.value()
		}
	}
	return map[string]any{"data": map[string]any{"grid": grid}}
}

type w3cError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	Stacktrace string `json:"stacktrace"`
}

func errorResponse(status, code, message string) []byte {
	return jsonResponse(status, map[string]w3cError{"value": {Error: code, Message: message}})
}

func buildInfo() string {
	return fmt.Sprintf("\nBuild info: version: '%s', revision: '%s'", version, revision)
}

func hostInfo() string {
	return fmt.Sprintf("\nHost info: host: '%s', ip: '%s'", Grid.Host, Grid.IP)
}

func systemInfo() string {
	return "\nSystem info: os.name: 'Linux', os.arch: 'amd64', os.version: '6.8.0-45-generic', java.version: '21.0.8'" +
		"\nDriver info: driver.version: unknown"
}

// newSessionError is the Grid's reply when the slot's "browser" exits right
// away, which is what a python or shell binary does.
func newSessionError(body []byte) []byte {
	s, ok := NewSessionRequest("POST", "/session", body)
	if !ok {
		return errorResponse("400 Bad Request", "invalid argument", "Unable to parse new session request"+buildInfo())
	}
	if s.Browser != "" && !strings.EqualFold(s.Browser, "chrome") {
		return errorResponse("500 Internal Server Error", "session not created",
			"Could not start a new session. No node supports the requested capabilities: browserName "+
				echo(s.Browser)+buildInfo())
	}
	binary := chromeBinary
	if s.Binary != "" {
		binary = echo(s.Binary)
	}
	return errorResponse("500 Internal Server Error", "session not created",
		"Could not start a new session. Response code 500. Message: session not created: Chrome failed to start: exited normally."+
			"\n  (session not created: DevToolsActivePort file doesn't exist)"+
			"\n  (The process started from chrome location "+binary+
			" is no longer running, so ChromeDriver is assuming that Chrome has crashed.) "+
			hostInfo()+buildInfo()+systemInfo())
}

var sessionIDRe = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

func invalidSession(p string) []byte {
	id, _, _ := strings.Cut(strings.TrimPrefix(p, "/session/"), "/")
	msg := "Unable to find session with ID: "
	if sessionIDRe.MatchString(id) {
		msg += id
	}
	return errorResponse("404 Not Found", "invalid session id", msg+buildInfo())
}

func unknownCommand(method, path string) []byte {
	return errorResponse("404 Not Found", "unknown command",
		"Unable to find handler for ("+method+") "+echo(path))
}

// echo bounds client-supplied text the Grid reflects in error messages.
func echo(s string) string {
	if len(s) > maxEchoLength {
		return s[:maxEchoLength]
	}
	return s
}
