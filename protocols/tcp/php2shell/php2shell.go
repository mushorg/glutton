// Package php2shell tags HTTP requests shaped like the PHP2Shell attack
// (CVE-2026-109618 and CVE-2026-109619, fixed in PHP 8.5.12, 8.4.27, 8.3.36 and
// 8.2.35). Public reporting says every known trigger is a multipart/form-data
// request that PHP parses before application code runs, usually driving the
// request past memory_limit, and that CVE-2026-109618 can leak freed memory
// through the upload-progress handler into a PHPSESSID response cookie.
//
// No exploit bytes have been published. The tags are heuristics on the request
// shape plus the probe shape of the public Assetnote scanner
// (github.com/assetnote/php2shell-scanner): an empty multipart boundary, field
// names nested 62 array levels deep, and a PHP2Shell/ User-Agent. The package
// only reads: it never changes the reply.
package php2shell

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const (
	// Indicator names set on Request.Indicators.
	UploadProgress    = "upload_progress"     // body carries the PHP_SESSION_UPLOAD_PROGRESS field
	ManyParts         = "many_parts"          // at least ManyPartsThreshold parts
	LargeBody         = "large_body"          // declared or actual size of at least LargeBodyThreshold
	LongSessionCookie = "long_session_cookie" // PHPSESSID cookie longer than MaxSessionCookie
	EmptyBoundary     = "empty_boundary"      // boundary= parameter present but empty
	NestedName        = "nested_name"         // a part name nested at least NestedNameThreshold array levels
	ScannerUserAgent  = "scanner_user_agent"  // User-Agent carries the public scanner's PHP2Shell/ token

	// ManyPartsThreshold is the part count that tags a request.
	ManyPartsThreshold = 100
	// LargeBodyThreshold is the body size in bytes that tags a request.
	LargeBodyThreshold = 1 << 20
	// NestedNameThreshold is the array nesting depth of a part name that tags a
	// request. The public scanner sends 63; PHP's max_input_nesting_level is 64.
	NestedNameThreshold = 32
	// MaxSessionCookie is the longest PHPSESSID value a normal client sends.
	MaxSessionCookie = 256
	// MaxScan caps the body bytes searched for parts and the progress field.
	MaxScan = 1 << 20
	// MaxBoundary caps the stored multipart boundary.
	MaxBoundary = 128

	uploadProgressField = "PHP_SESSION_UPLOAD_PROGRESS"
	scannerToken        = "php2shell/"
)

// Request is the PHP2Shell-specific part of a decoded HTTP read frame.
type Request struct {
	Indicators    []string `json:"indicators"`
	Parts         int      `json:"parts,omitempty"`          // multipart parts seen in the scanned bytes
	ContentLength int64    `json:"content_length,omitempty"` // larger of the declared and received size
	Boundary      string   `json:"boundary,omitempty"`
	MaxDepth      int      `json:"max_depth,omitempty"` // deepest array nesting of a part name
	Truncated     bool     `json:"truncated,omitempty"` // scan cap or boundary cap applied
}

// Inspect returns nil unless the request is multipart/form-data and matches at
// least one indicator.
func Inspect(header http.Header, body []byte) *Request {
	contentType := header.Get("Content-Type")
	// An empty boundary= is an invalid parameter, but the media type still parses.
	mediaType, params, err := mime.ParseMediaType(contentType)
	if (err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter)) || mediaType != "multipart/form-data" {
		return nil
	}
	boundary, hasBoundary := params["boundary"]
	if !hasBoundary {
		boundary, hasBoundary = rawBoundary(contentType)
	}
	req := &Request{ContentLength: int64(len(body))}
	if declared, err := strconv.ParseInt(strings.TrimSpace(header.Get("Content-Length")), 10, 64); err == nil && declared > req.ContentLength {
		req.ContentLength = declared
	}
	scanned := body
	if len(scanned) > MaxScan {
		scanned, req.Truncated = scanned[:MaxScan], true
	}

	if bytes.Contains(scanned, []byte(uploadProgressField)) {
		req.Indicators = append(req.Indicators, UploadProgress)
	}
	if hasBoundary {
		req.Parts = countParts(scanned, boundary)
		if len(boundary) > MaxBoundary {
			boundary, req.Truncated = boundary[:MaxBoundary], true
		}
		req.Boundary = boundary
		if boundary == "" {
			req.Indicators = append(req.Indicators, EmptyBoundary)
		}
	}
	if req.Parts >= ManyPartsThreshold {
		req.Indicators = append(req.Indicators, ManyParts)
	}
	if req.ContentLength >= LargeBodyThreshold {
		req.Indicators = append(req.Indicators, LargeBody)
	}
	if sessionCookieLen(header) > MaxSessionCookie {
		req.Indicators = append(req.Indicators, LongSessionCookie)
	}
	if req.MaxDepth = maxNameDepth(scanned); req.MaxDepth >= NestedNameThreshold {
		req.Indicators = append(req.Indicators, NestedName)
	}
	if strings.Contains(strings.ToLower(header.Get("User-Agent")), scannerToken) {
		req.Indicators = append(req.Indicators, ScannerUserAgent)
	}
	if len(req.Indicators) == 0 {
		return nil
	}
	return req
}

// countParts counts "--boundary" delimiters that open a part, not the closing
// "--boundary--".
func countParts(body []byte, boundary string) int {
	delim := []byte("--" + boundary)
	n := 0
	for rest := body; ; {
		i := bytes.Index(rest, delim)
		if i < 0 {
			return n
		}
		rest = rest[i+len(delim):]
		if !bytes.HasPrefix(rest, []byte("--")) {
			n++
		}
	}
}

// rawBoundary reads a boundary parameter that mime.ParseMediaType rejected,
// such as an empty boundary=.
func rawBoundary(contentType string) (string, bool) {
	for _, param := range strings.Split(contentType, ";")[1:] {
		name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "boundary") {
			return strings.Trim(strings.TrimSpace(value), `"`), true
		}
	}
	return "", false
}

// maxNameDepth returns the deepest array nesting ("[" count) of any part name,
// quoted or not, in the Content-Disposition headers of body.
func maxNameDepth(body []byte) int {
	deepest := 0
	for rest := body; ; {
		i := bytes.Index(rest, []byte("name="))
		if i < 0 {
			return deepest
		}
		prefixed := i > 0 && rest[i-1] != ' ' && rest[i-1] != ';' && rest[i-1] != ':'
		rest = rest[i+len("name="):]
		if prefixed { // filename=, not name=
			continue
		}
		value := bytes.TrimPrefix(rest, []byte(`"`))
		if end := bytes.IndexAny(value, "\";\r\n"); end >= 0 {
			value = value[:end]
		}
		if depth := bytes.Count(value, []byte("[")); depth > deepest {
			deepest = depth
		}
	}
}

func sessionCookieLen(header http.Header) int {
	longest := 0
	for _, line := range header.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.EqualFold(name, "PHPSESSID") && len(value) > longest {
				longest = len(value)
			}
		}
	}
	return longest
}
