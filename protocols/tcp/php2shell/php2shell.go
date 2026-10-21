// Package php2shell tags HTTP requests shaped like the PHP2Shell attack
// (CVE-2026-109618 and CVE-2026-109619, fixed in PHP 8.5.12, 8.4.27, 8.3.36 and
// 8.2.35). Public reporting says every known trigger is a multipart/form-data
// request that PHP parses before application code runs, usually driving the
// request past memory_limit, and that CVE-2026-109618 can leak freed memory
// through the upload-progress handler into a PHPSESSID response cookie.
//
// No exploit bytes or indicators have been published, so the tags are
// heuristics on the request shape, not signatures. The package only reads: it
// never changes the reply.
package php2shell

import (
	"bytes"
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

	// ManyPartsThreshold is the part count that tags a request.
	ManyPartsThreshold = 100
	// LargeBodyThreshold is the body size in bytes that tags a request.
	LargeBodyThreshold = 1 << 20
	// MaxSessionCookie is the longest PHPSESSID value a normal client sends.
	MaxSessionCookie = 256
	// MaxScan caps the body bytes searched for parts and the progress field.
	MaxScan = 1 << 20
	// MaxBoundary caps the stored multipart boundary.
	MaxBoundary = 128

	uploadProgressField = "PHP_SESSION_UPLOAD_PROGRESS"
)

// Request is the PHP2Shell-specific part of a decoded HTTP read frame.
type Request struct {
	Indicators    []string `json:"indicators"`
	Parts         int      `json:"parts,omitempty"`          // multipart parts seen in the scanned bytes
	ContentLength int64    `json:"content_length,omitempty"` // larger of the declared and received size
	Boundary      string   `json:"boundary,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"` // scan cap or boundary cap applied
}

// Inspect returns nil unless the request is multipart/form-data and matches at
// least one indicator.
func Inspect(header http.Header, body []byte) *Request {
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		return nil
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
	if boundary := params["boundary"]; boundary != "" {
		req.Parts = countParts(scanned, boundary)
		if len(boundary) > MaxBoundary {
			boundary, req.Truncated = boundary[:MaxBoundary], true
		}
		req.Boundary = boundary
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
