// Package plex2shell tags HTTP requests shaped like the Plex2Shell attack, a
// four-bug chain in Plex Media Server before 1.43.3.10861 (CVE-2026-96652,
// -96654, -96655 and -96656; write-up and PoC published 2026-10-16, first
// exploitation seen 2026-10-17). The chain starts with an unauthenticated
// request to /player/timeline/subscribe whose callback host starts with a
// loopback address but resolves elsewhere (127.0.0.1.<ip>.sslip.io), so the
// server trusts it and calls back into a plugin invocation.
//
// The only request bytes seen in public are one Zeek log line from a honeypot
// operator, so the tags are heuristics on that shape, not signatures. The
// package never dials the callback host: it records it and answers like an
// unclaimed, unpatched server on tcp/32400. It does no I/O.
package plex2shell

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Port is the Plex Media Server port; every path there is the Plex persona.
	Port = 32400

	// Indicator names set on Request.Indicators.
	SubscribePath      = "subscribe_path"       // /player/timeline/subscribe
	LoopbackPrefixHost = "loopback_prefix_host" // 127.0.0.1.<label>... callback host
	AgentCallback      = "agent_callback"       // com.plexapp.agents.* plugin function reference
	PoCClient          = "poc_client"           // X-Plex-Target-Client-Identifier starting with poc_

	// MaxScan caps the query and header text searched for indicators.
	MaxScan = 16 << 10
	// MaxField caps each stored free-text field.
	MaxField = 256

	subscribePath = "/player/timeline/subscribe"
	targetClient  = "X-Plex-Target-Client-Identifier"

	// serverVersion is a Plex Media Server build older than the fix.
	serverVersion = "1.43.2.10389-5f3b9a7c1"
)

var (
	// loopbackHostRE matches a host that begins with a loopback literal and
	// carries more labels after it. A plain 127.0.0.1:32400 does not match.
	loopbackHostRE = regexp.MustCompile(`(?i)\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0)\.[a-z0-9][a-z0-9.-]{0,240}(?::(\d{1,5}))?`)
	// wildcardIPRE pulls the embedded address out of sslip.io / nip.io names.
	wildcardIPRE = regexp.MustCompile(`(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})\.(?:sslip|nip)\.io`)
	agentRE      = regexp.MustCompile(`(?i)com\.plexapp\.agents\.[a-z0-9_.-]{1,64}(?:/function/[a-z0-9_]{1,64})?`)
)

// Request is the Plex2Shell-specific part of a decoded HTTP read frame.
type Request struct {
	Indicators       []string `json:"indicators"`
	CallbackHost     string   `json:"callback_host,omitempty"`     // host the server was told to call back
	CallbackIP       string   `json:"callback_ip,omitempty"`       // address embedded in a sslip.io / nip.io name
	CallbackPort     int      `json:"callback_port,omitempty"`     // port of the callback host
	Agent            string   `json:"agent,omitempty"`             // plugin reference, e.g. com.plexapp.agents.thetvdb/function/GetResultFromNetwork
	ClientIdentifier string   `json:"client_identifier,omitempty"` // X-Plex-Target-Client-Identifier
	Truncated        bool     `json:"truncated,omitempty"`         // scan cap or field cap applied
}

// Inspect returns nil unless the request matches at least one indicator.
func Inspect(path, rawQuery string, header http.Header) *Request {
	req := &Request{}
	text := rawQuery
	if len(text) > MaxScan {
		text, req.Truncated = text[:MaxScan], true
	}
	// Callbacks are nested inside a query value, so look at the decoded forms
	// as well as the raw one.
	scan := text
	for decoded := text; ; {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		scan += "\n" + next
		decoded = next
	}
	for name, values := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-plex-") {
			for _, v := range values {
				scan += "\n" + v
			}
		}
	}
	if len(scan) > 4*MaxScan {
		scan, req.Truncated = scan[:4*MaxScan], true
	}

	if strings.EqualFold(strings.TrimRight(path, "/"), subscribePath) {
		req.Indicators = append(req.Indicators, SubscribePath)
	}
	if m := loopbackHostRE.FindStringSubmatch(scan); m != nil {
		req.Indicators = append(req.Indicators, LoopbackPrefixHost)
		host := m[0]
		if m[1] != "" {
			req.CallbackPort, _ = strconv.Atoi(m[1])
			host = strings.TrimSuffix(host, ":"+m[1])
		}
		req.CallbackHost = capField(host, &req.Truncated)
		req.CallbackIP = embeddedIP(host)
	}
	// The raw form may still be encoded, so take the longest match over all forms.
	agent := ""
	for _, m := range agentRE.FindAllString(scan, -1) {
		if len(m) > len(agent) {
			agent = m
		}
	}
	if agent != "" {
		req.Indicators = append(req.Indicators, AgentCallback)
		req.Agent = capField(agent, &req.Truncated)
	}
	if id := clientIdentifier(rawQuery, header); id != "" {
		req.ClientIdentifier = capField(id, &req.Truncated)
		if strings.HasPrefix(strings.ToLower(id), "poc_") {
			req.Indicators = append(req.Indicators, PoCClient)
		}
	}
	if len(req.Indicators) == 0 {
		return nil
	}
	return req
}

func clientIdentifier(rawQuery string, header http.Header) string {
	if id := header.Get(targetClient); id != "" {
		return id
	}
	values, _ := url.ParseQuery(rawQuery)
	for name, v := range values {
		if strings.EqualFold(name, targetClient) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// embeddedIP returns the address a wildcard-DNS name resolves to, judged from
// the name alone. Nothing is resolved.
func embeddedIP(host string) string {
	m := wildcardIPRE.FindStringSubmatch(strings.ToLower(host))
	if m == nil {
		return ""
	}
	ip := net.ParseIP(strings.Join(m[1:5], "."))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func capField(s string, truncated *bool) string {
	if len(s) > MaxField {
		*truncated = true
		return s[:MaxField]
	}
	return s
}

var (
	machineOnce sync.Once
	machineID   string
)

// machineIdentifier is the per-process server ID, random per sensor so
// sensors do not share one.
func machineIdentifier() string {
	machineOnce.Do(func() {
		b := make([]byte, 20)
		if _, err := rand.Read(b); err != nil {
			copy(b, "plex-media-server-0000")
		}
		machineID = hex.EncodeToString(b)
	})
	return machineID
}

// Respond answers like an unclaimed, unpatched Plex Media Server reached
// without a token: /identity and the player timeline calls succeed, everything
// else is 401. now stamps the Date header.
func Respond(method, path string, now time.Time) []byte {
	if method != http.MethodGet {
		return unauthorized(now)
	}
	switch strings.ToLower(strings.TrimRight(path, "/")) {
	case "/identity":
		return reply(now, "200 OK", "text/xml;charset=utf-8", fmt.Sprintf(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<MediaContainer size=\"0\" claimed=\"0\" machineIdentifier=\"%s\" version=\"%s\">\n</MediaContainer>\n",
			machineIdentifier(), serverVersion))
	case subscribePath, "/player/timeline/unsubscribe":
		return reply(now, "200 OK", "text/xml;charset=utf-8",
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response code=\"200\" status=\"OK\" />\n")
	}
	return unauthorized(now)
}

func unauthorized(now time.Time) []byte {
	return reply(now, "401 Unauthorized", "text/html",
		"<html><head><title>Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>")
}

func reply(now time.Time, status, contentType, body string) []byte {
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %s\r\nX-Plex-Protocol: 1.0\r\nContent-Length: %d\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nDate: %s\r\n\r\n%s",
		status, len(body), contentType, now.UTC().Format(http.TimeFormat), body))
}
