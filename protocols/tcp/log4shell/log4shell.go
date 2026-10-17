// Package log4shell finds Log4Shell (CVE-2021-44228) JNDI lookups in HTTP
// requests. Scanners and exploits put ${jndi:ldap://host/x} in the URL, the
// headers (User-Agent, X-Api-Version, ...) or the body, often obfuscated with
// nested lookups such as ${${lower:j}ndi:...} or ${${::-j}${::-n}di:...}.
//
// The package only reads: it never resolves or dials the host in a lookup.
// Detection locations follow Log4Pot (thomaspatzke/Log4Pot, GPL-3.0, used as a
// behavior reference only; no code is ported).
package log4shell

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	// MaxLookups caps the lookups recorded per request.
	MaxLookups = 16
	// MaxExpression caps the stored raw and resolved lookup text.
	MaxExpression = 512
	// MaxScan caps the bytes of one field or the body that are scanned.
	MaxScan = 16 * 1024
	// maxDepth bounds nested ${...} evaluation.
	maxDepth = 8
)

// Lookup is one JNDI lookup found in a request.
type Lookup struct {
	Location string `json:"location"`           // "path", "query", "body" or "header:<Name>"
	Raw      string `json:"raw"`                // the ${...} expression as sent (URL-decoded)
	Resolved string `json:"resolved,omitempty"` // after evaluating nested lookups, e.g. jndi:ldap://h/x
}

// Request is the Log4Shell-specific part of a decoded HTTP read frame.
type Request struct {
	Lookups   []Lookup `json:"lookups"`
	Truncated bool     `json:"truncated,omitempty"` // lookup cap, expression cap or scan cap applied
}

// Inspect scans the path, query, headers and body of a request. It returns
// nil when no JNDI lookup is present. escapedPath and rawQuery are as sent.
func Inspect(escapedPath, rawQuery string, header http.Header, body []byte) *Request {
	req := &Request{}
	scan := func(location, value string) {
		if len(value) > MaxScan {
			value, req.Truncated = value[:MaxScan], true
		}
		req.find(location, value)
		// Scanners URL-encode the payload in the request line and form bodies.
		if dec, err := url.PathUnescape(value); err == nil && dec != value {
			req.find(location, dec)
		}
		if dec, err := url.QueryUnescape(value); err == nil && dec != value {
			req.find(location, dec)
		}
	}
	scan("path", escapedPath)
	scan("query", rawQuery)
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range header[name] {
			scan("header:"+name, v)
		}
	}
	scan("body", string(body))
	if len(req.Lookups) == 0 {
		return nil
	}
	return req
}

func (r *Request) find(location, s string) {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '$' || s[i+1] != '{' {
			continue
		}
		end := matchBrace(s, i+1)
		if end < 0 {
			continue
		}
		raw := s[i : end+1]
		resolved := resolve(raw, 0)
		if !strings.HasPrefix(strings.ToLower(resolved), "${jndi:") {
			continue
		}
		r.add(Lookup{Location: location, Raw: raw, Resolved: strings.TrimSuffix(strings.TrimPrefix(resolved, "${"), "}")})
		i = end
	}
}

func (r *Request) add(l Lookup) {
	if len(r.Lookups) >= MaxLookups {
		r.Truncated = true
		return
	}
	var cut bool
	if len(l.Raw) > MaxExpression {
		l.Raw, cut = l.Raw[:MaxExpression], true
	}
	if len(l.Resolved) > MaxExpression {
		l.Resolved, cut = l.Resolved[:MaxExpression], true
	}
	if "${"+l.Resolved+"}" == l.Raw {
		l.Resolved = ""
	}
	r.Truncated = r.Truncated || cut
	for _, have := range r.Lookups {
		if have == l {
			return
		}
	}
	r.Lookups = append(r.Lookups, l)
}

// matchBrace returns the index of the } closing the { at s[open], or -1.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// resolve evaluates the Log4j lookups in s that matter for de-obfuscation:
// lower:, upper:, and any "name:-default" form (${::-j}, ${env:X:-j}). Other
// lookups are kept as written, except that jndi: itself is left intact.
func resolve(s string, depth int) string {
	if depth > maxDepth {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			out.WriteByte(s[i])
			continue
		}
		end := matchBrace(s, i+1)
		if end < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(evalLookup(s[i+2:end], depth+1))
		i = end
	}
	return out.String()
}

func evalLookup(inner string, depth int) string {
	body := resolve(inner, depth)
	lower := strings.ToLower(body)
	switch {
	case strings.HasPrefix(lower, "lower:"):
		return strings.ToLower(body[len("lower:"):])
	case strings.HasPrefix(lower, "upper:"):
		return strings.ToUpper(body[len("upper:"):])
	}
	if strings.HasPrefix(lower, "jndi:") {
		// The caller wants the expression back so it can recognize it.
		return "${" + body + "}"
	}
	if i := strings.Index(body, ":-"); i >= 0 {
		return body[i+2:]
	}
	return "${" + body + "}"
}
