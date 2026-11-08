// Package dockerapi emulates the unauthenticated read-only surface of a Docker
// Engine API (dockerd on tcp/2375 plain, tcp/2376 TLS): the ping, version and
// empty container/image lists that scanners use to fingerprint an exposed
// daemon. Nothing is executed; every other route is Docker's 404. The package
// does no I/O.
package dockerapi

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	// PlainPort and TLSPort are the IANA Docker ports; every path there is the
	// Docker persona.
	PlainPort = 2375
	TLSPort   = 2376

	// engineVersion and apiVersion must match resources/docker_api.json.
	engineVersion = "20.10.9"
	apiVersion    = "1.41"
)

// versionPrefix matches the optional /vX.Y API version prefix of a route.
var versionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)

// IsPort reports whether port is a Docker Engine API port.
func IsPort(port uint16) bool {
	return port == PlainPort || port == TLSPort
}

// Route strips the /vX.Y version prefix and a trailing slash from path.
func Route(path string) string {
	if loc := versionPrefix.FindStringIndex(path); loc != nil {
		path = "/" + path[loc[1]:]
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

// Respond builds the dockerd reply for a request. version is the GET /version
// JSON body; now sets the Date header.
func Respond(method, path string, version []byte, now time.Time) []byte {
	get := method == http.MethodGet || method == http.MethodHead
	switch route := Route(path); {
	case route == "/_ping" && get:
		return response(method, "200 OK", "text/plain; charset=utf-8", []byte("OK"), true, now)
	case route == "/version" && get:
		return response(method, "200 OK", "application/json", append(append([]byte{}, version...), '\n'), false, now)
	case (route == "/containers/json" || route == "/images/json") && get:
		return response(method, "200 OK", "application/json", []byte("[]\n"), false, now)
	}
	return response(method, "404 Not Found", "application/json", []byte("{\"message\":\"page not found\"}\n"), false, now)
}

func response(method, status, contentType string, body []byte, ping bool, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&b, "Api-Version: %s\r\n", apiVersion)
	if ping {
		b.WriteString("Builder-Version: 2\r\n")
		b.WriteString("Cache-Control: no-cache, no-store, must-revalidate\r\n")
	}
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	b.WriteString("Docker-Experimental: false\r\n")
	b.WriteString("Ostype: linux\r\n")
	if ping {
		b.WriteString("Pragma: no-cache\r\n")
	}
	fmt.Fprintf(&b, "Server: Docker/%s (linux)\r\n", engineVersion)
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(http.TimeFormat))
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	if method == http.MethodHead {
		return []byte(b.String())
	}
	return append([]byte(b.String()), body...)
}
