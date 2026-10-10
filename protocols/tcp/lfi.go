package tcp

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// lfiBasenames maps the basename of an LFI include target to an embedded
// canned body under resources/lfi/.
var lfiBasenames = map[string]string{
	"amportal.conf": "resources/lfi/amportal.conf",
	"passwd":        "resources/lfi/passwd",
	"hosts":         "resources/lfi/hosts",
	"win.ini":       "resources/lfi/win.ini",
}

// LFIResponse returns a canned HTTP 200 for GET queries that look like a
// local-file-include of a known file. The request path is ignored; only the
// raw query is inspected. Returns nil when there is no match.
func LFIResponse(rawQuery string) []byte {
	target := extractLFITarget(rawQuery)
	if target == "" {
		return nil
	}
	base := strings.ToLower(path.Base(target))
	if base == "." || base == "/" || base == "" {
		return nil
	}
	resPath, ok := lfiBasenames[base]
	if !ok {
		return nil
	}
	data, err := Res.ReadFile(resPath)
	if err != nil {
		return nil
	}
	return append([]byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",
		len(data),
	)), data...)
}

// extractLFITarget returns the included file path from a raw query string, or
// empty if the query does not look like an LFI.
func extractLFITarget(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(rawQuery)
	if err != nil {
		decoded = rawQuery
	}
	if !looksLikeLFI(rawQuery) && !looksLikeLFI(decoded) {
		return ""
	}

	// Prefer the decoded form for path extraction after traversal markers.
	for _, candidate := range []string{decoded, rawQuery} {
		if target := targetAfterTraversal(candidate); target != "" {
			return target
		}
	}
	return ""
}

func looksLikeLFI(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(s, "../") || strings.Contains(lower, "..%2f") {
		return true
	}
	if strings.Contains(lower, "%00") || strings.Contains(s, "\x00") {
		return true
	}
	return false
}

// targetAfterTraversal finds the path-looking segment after the last "../"
// (or decoded equivalent) and strips a trailing null / %00.
func targetAfterTraversal(s string) string {
	// Normalize encoded traversal so the last "../" search works on decoded text.
	normalized := strings.ReplaceAll(s, "..%2f", "../")
	normalized = strings.ReplaceAll(normalized, "..%2F", "../")

	idx := strings.LastIndex(normalized, "../")
	if idx < 0 {
		// Null-byte LFI without traversal: take a value that names a known file.
		return targetWithNullByte(normalized)
	}
	rest := normalized[idx+len("../"):]
	// Collapse leading slashes from patterns like ..//etc/...
	rest = strings.TrimLeft(rest, "/")
	if rest == "" {
		return ""
	}
	// Cut at & (next query param) or whitespace.
	if i := strings.IndexAny(rest, "&\r\n "); i >= 0 {
		rest = rest[:i]
	}
	rest = stripNullSuffix(rest)
	if rest == "" {
		return ""
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return path.Clean(rest)
}

func targetWithNullByte(s string) string {
	if !strings.Contains(s, "\x00") && !strings.Contains(strings.ToLower(s), "%00") {
		return ""
	}
	for _, part := range strings.Split(s, "&") {
		_, val, ok := strings.Cut(part, "=")
		if !ok {
			val = part
		}
		val = stripNullSuffix(val)
		val = strings.TrimLeft(val, "/")
		if val == "" {
			continue
		}
		base := strings.ToLower(path.Base(val))
		if _, known := lfiBasenames[base]; !known {
			continue
		}
		if !strings.HasPrefix(val, "/") {
			val = "/" + val
		}
		return path.Clean(val)
	}
	return ""
}

func stripNullSuffix(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	lower := strings.ToLower(s)
	if i := strings.Index(lower, "%00"); i >= 0 {
		s = s[:i]
	}
	return s
}
