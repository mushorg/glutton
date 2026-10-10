// Package icap parses and builds ICAP/1.0 (RFC 3507), the Internet Content
// Adaptation Protocol spoken by proxy filters (c-icap, Squid adaptation,
// antivirus gateways) on tcp/1344. Requests look like HTTP:
//
//	OPTIONS icap://icap.example:1344/echo ICAP/1.0\r\n
//	Host: icap.example:1344\r\n
//	\r\n
//
// REQMOD and RESPMOD carry an encapsulated HTTP message. The Encapsulated
// header gives byte offsets of the HTTP header sections (req-hdr, res-hdr)
// and of the body (req-body, res-body, opt-body or null-body). The body is
// chunked; with a Preview header the client sends only the first bytes and
// ends with "0\r\n\r\n" (more to come after 100 Continue) or "0; ieof\r\n\r\n"
// (that was all).
package icap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	MethodOptions = "OPTIONS"
	MethodReqmod  = "REQMOD"
	MethodRespmod = "RESPMOD"

	maxHeaders = 64
	// maxEncapsulatedHeaders caps the encapsulated HTTP header sections.
	maxEncapsulatedHeaders = 64 * 1024
	// maxDiscard bounds how many body bytes past the cap are skipped to stay in sync.
	maxDiscard      = 1 << 20
	maxChunkSizeHex = 16
)

var (
	ErrMalformed    = errors.New("malformed ICAP request")
	ErrLineTooLong  = errors.New("ICAP line too long")
	ErrBodyTooLarge = errors.New("ICAP body too large")
)

// Section is one entry of the Encapsulated header.
type Section struct {
	Name   string
	Offset int
}

// Request is a parsed ICAP request.
type Request struct {
	Method       string
	URI          string
	Service      string // path of the ICAP URI, e.g. "/" or "/avscan"
	Version      string
	Headers      map[string]string // keys lower-cased
	Encapsulated []Section
	ReqHdr       []byte // encapsulated HTTP request header block
	ResHdr       []byte // encapsulated HTTP response header block
	BodyType     string // req-body, res-body, opt-body or null-body; empty without Encapsulated
	Body         []byte // de-chunked body, capped
	Preview      int    // Preview header value, -1 when absent
	IEOF         bool   // the preview ended with "0; ieof"
}

// Header returns a header value by case-insensitive name.
func (r Request) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// HasBody reports whether a chunked body follows the encapsulated headers.
func (r Request) HasBody() bool {
	return r.BodyType != "" && r.BodyType != "null-body"
}

// NeedsContinue reports whether the client sent a preview and waits for
// 100 Continue before sending the rest of the body.
func (r Request) NeedsContinue() bool {
	return r.HasBody() && r.Preview >= 0 && !r.IEOF
}

// Allows204 reports whether the client accepts 204 outside a preview.
func (r Request) Allows204() bool {
	for _, v := range strings.Split(r.Header("Allow"), ",") {
		if strings.TrimSpace(v) == "204" {
			return true
		}
	}
	return false
}

// HTTPRequestLine returns the first line of the encapsulated HTTP request.
func (r Request) HTTPRequestLine() string {
	return firstLine(r.ReqHdr)
}

// HTTPStatusLine returns the first line of the encapsulated HTTP response.
func (r Request) HTTPStatusLine() string {
	return firstLine(r.ResHdr)
}

func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(b, []byte("\n"))
	return strings.TrimRight(string(line), "\r")
}

// LooksLikeICAP reports whether the first bytes of a stream start an ICAP request.
func LooksLikeICAP(snip []byte) bool {
	for _, m := range []string{MethodOptions, MethodReqmod, MethodRespmod} {
		if bytes.HasPrefix(snip, []byte(m+" icap://")) {
			return true
		}
	}
	return false
}

// reader tracks every consumed byte so callers can store the wire request.
type reader struct {
	r   *bufio.Reader
	raw bytes.Buffer
}

func (rd *reader) line() (string, error) {
	line, err := rd.r.ReadSlice('\n')
	rd.raw.Write(line)
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", ErrLineTooLong
	}
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// lineInBody is line with a bare EOF turned into io.ErrUnexpectedEOF.
func (rd *reader) lineInBody() (string, error) {
	line, err := rd.line()
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return line, err
}

// ReadRequest reads one request from r: the ICAP head, the encapsulated HTTP
// headers and, when present, the chunked body (or its preview). raw holds
// every byte consumed (body data capped at maxBody) even when err is non-nil.
// truncated is set when body bytes past maxBody were discarded. A clean EOF
// before the first byte returns io.EOF with empty raw.
func ReadRequest(r *bufio.Reader, maxBody int) (req Request, raw []byte, truncated bool, err error) {
	rd := &reader{r: r}
	req.Preview = -1

	line, err := rd.line()
	if err != nil {
		return req, rd.raw.Bytes(), false, err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "ICAP/") {
		return req, rd.raw.Bytes(), false, fmt.Errorf("%w: request line %q", ErrMalformed, line)
	}
	req.Method, req.URI, req.Version = parts[0], parts[1], parts[2]
	req.Service = servicePath(req.URI)
	req.Headers = map[string]string{}

	for i := 0; ; i++ {
		if i > maxHeaders {
			return req, rd.raw.Bytes(), false, fmt.Errorf("%w: too many headers", ErrMalformed)
		}
		line, err := rd.lineInBody()
		if err != nil {
			return req, rd.raw.Bytes(), false, err
		}
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return req, rd.raw.Bytes(), false, fmt.Errorf("%w: header %q", ErrMalformed, line)
		}
		req.Headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	if p := req.Header("Preview"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return req, rd.raw.Bytes(), false, fmt.Errorf("%w: Preview %q", ErrMalformed, p)
		}
		req.Preview = n
	}

	if enc := req.Header("Encapsulated"); enc != "" {
		sections, err := ParseEncapsulated(enc)
		if err != nil {
			return req, rd.raw.Bytes(), false, err
		}
		req.Encapsulated = sections
		last := sections[len(sections)-1]
		req.BodyType = last.Name
		hdrs := make([]byte, last.Offset)
		n, err := io.ReadFull(r, hdrs)
		rd.raw.Write(hdrs[:n])
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return req, rd.raw.Bytes(), false, err
		}
		for i, s := range sections[:len(sections)-1] {
			block := hdrs[s.Offset:sections[i+1].Offset]
			switch s.Name {
			case "req-hdr":
				req.ReqHdr = block
			case "res-hdr":
				req.ResHdr = block
			}
		}
	}

	if !req.HasBody() {
		return req, rd.raw.Bytes(), false, nil
	}
	body, ieof, truncated, err := rd.chunked(maxBody)
	req.Body, req.IEOF = body, ieof
	return req, rd.raw.Bytes(), truncated, err
}

// ReadChunked reads the rest of a body after 100 Continue. raw holds the wire
// bytes consumed (data capped at maxBody).
func ReadChunked(r *bufio.Reader, maxBody int) (body, raw []byte, truncated bool, err error) {
	rd := &reader{r: r}
	body, _, truncated, err = rd.chunked(maxBody)
	return body, rd.raw.Bytes(), truncated, err
}

// chunked reads a chunked body up to the zero-size chunk and its trailers.
func (rd *reader) chunked(maxBody int) (body []byte, ieof, truncated bool, err error) {
	discarded := 0
	for {
		line, err := rd.lineInBody()
		if err != nil {
			return body, false, truncated, err
		}
		sizeStr, ext, _ := strings.Cut(line, ";")
		sizeStr = strings.TrimSpace(sizeStr)
		if sizeStr == "" || len(sizeStr) > maxChunkSizeHex {
			return body, false, truncated, fmt.Errorf("%w: chunk size %q", ErrMalformed, line)
		}
		size, err := strconv.ParseUint(sizeStr, 16, 63)
		if err != nil {
			return body, false, truncated, fmt.Errorf("%w: chunk size %q", ErrMalformed, line)
		}
		if size == 0 {
			ieof = strings.TrimSpace(ext) == "ieof"
			// trailers, then the blank line ending the body
			for i := 0; ; i++ {
				if i > maxHeaders {
					return body, ieof, truncated, fmt.Errorf("%w: too many trailers", ErrMalformed)
				}
				line, err := rd.lineInBody()
				if err != nil {
					return body, ieof, truncated, err
				}
				if line == "" {
					return body, ieof, truncated, nil
				}
			}
		}
		keep := int(min(size, uint64(maxBody-len(body))))
		rest := int64(size) - int64(keep)
		if rest > 0 {
			truncated = true
			if int64(discarded)+rest > maxDiscard {
				return body, false, truncated, ErrBodyTooLarge
			}
		}
		data := make([]byte, keep)
		n, err := io.ReadFull(rd.r, data)
		rd.raw.Write(data[:n])
		body = append(body, data[:n]...)
		if err == nil && rest > 0 {
			var skipped int64
			skipped, err = io.CopyN(io.Discard, rd.r, rest)
			discarded += int(skipped)
		}
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return body, false, truncated, err
		}
		end, err := rd.lineInBody()
		if err != nil {
			return body, false, truncated, err
		}
		if end != "" {
			return body, false, truncated, fmt.Errorf("%w: missing CRLF after chunk", ErrMalformed)
		}
	}
}

// ParseEncapsulated parses an Encapsulated header value such as
// "req-hdr=0, res-hdr=137, res-body=296". Offsets must not decrease, the
// last entry must be a body entry, and the header sections stay under
// maxEncapsulatedHeaders.
func ParseEncapsulated(v string) ([]Section, error) {
	var sections []Section
	prev := 0
	for _, part := range strings.Split(v, ",") {
		name, off, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, fmt.Errorf("%w: Encapsulated %q", ErrMalformed, v)
		}
		n, err := strconv.Atoi(strings.TrimSpace(off))
		if err != nil || n < prev || n > maxEncapsulatedHeaders {
			return nil, fmt.Errorf("%w: Encapsulated %q", ErrMalformed, v)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "req-hdr", "res-hdr", "req-body", "res-body", "opt-body", "null-body":
		default:
			return nil, fmt.Errorf("%w: Encapsulated %q", ErrMalformed, v)
		}
		// nothing may follow the body entry
		if len(sections) > 0 && isBody(sections[len(sections)-1].Name) {
			return nil, fmt.Errorf("%w: Encapsulated %q", ErrMalformed, v)
		}
		sections = append(sections, Section{Name: name, Offset: n})
		prev = n
	}
	if len(sections) == 0 || !isBody(sections[len(sections)-1].Name) {
		return nil, fmt.Errorf("%w: Encapsulated %q", ErrMalformed, v)
	}
	return sections, nil
}

func isBody(name string) bool {
	return strings.HasSuffix(name, "-body")
}

// servicePath returns the path of an icap:// URI, "/" when it has none.
func servicePath(uri string) string {
	rest, ok := strings.CutPrefix(uri, "icap://")
	if !ok {
		if strings.HasPrefix(uri, "/") {
			return uri
		}
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path := rest[i:]
		if q := strings.IndexByte(path, '?'); q >= 0 {
			path = path[:q]
		}
		return path
	}
	return "/"
}

// Persona is the server identity announced in responses.
type Persona struct {
	Server  string // Server header, e.g. "C-ICAP/0.5.10"
	Service string // Service header in OPTIONS
	ISTag   string // ISTag value without quotes
}

// statusText follows c-icap's reason phrases.
var statusText = map[int]string{
	100: "Continue",
	200: "OK",
	204: "Unmodified",
	400: "Bad request",
	404: "Service not found",
	405: "Method not allowed for service",
	501: "Method not implemented",
}

// StatusText returns the reason phrase for an ICAP status code.
func StatusText(code int) string {
	return statusText[code]
}

func httpDate(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

type builder struct{ bytes.Buffer }

func (b *builder) header(k, v string) {
	b.WriteString(k + ": " + v + "\r\n")
}

func (b *builder) status(code int) {
	fmt.Fprintf(b, "ICAP/1.0 %d %s\r\n", code, statusText[code])
}

func (b *builder) common(p Persona, date time.Time) {
	b.header("Server", p.Server)
	b.header("Connection", "keep-alive")
	b.header("ISTag", `"`+p.ISTag+`"`)
	b.header("Date", httpDate(date))
}

// BuildOptions answers OPTIONS for a service that supports both methods.
func BuildOptions(p Persona, date time.Time) []byte {
	var b builder
	b.status(200)
	b.header("Methods", "RESPMOD, REQMOD")
	b.header("Service", p.Service)
	b.header("ISTag", `"`+p.ISTag+`"`)
	b.header("Transfer-Preview", "*")
	b.header("Options-TTL", "3600")
	b.header("Date", httpDate(date))
	b.header("Preview", "1024")
	b.header("Allow", "204")
	b.header("Max-Connections", "600")
	b.header("X-Include", "X-Authenticated-User, X-Authenticated-Groups")
	b.header("Encapsulated", "null-body=0")
	b.WriteString("\r\n")
	return b.Bytes()
}

// BuildContinue is the interim reply that asks for the rest of a previewed body.
func BuildContinue() []byte {
	return []byte("ICAP/1.0 100 Continue\r\n\r\n")
}

// BuildStatus builds a reply without encapsulated data (204, 4xx, 5xx).
func BuildStatus(code int, p Persona, date time.Time) []byte {
	var b builder
	b.status(code)
	b.common(p, date)
	b.header("Encapsulated", "null-body=0")
	b.WriteString("\r\n")
	return b.Bytes()
}

// BuildEcho returns the encapsulated message unmodified: the HTTP request for
// REQMOD, the HTTP response for RESPMOD, with the body re-chunked.
func BuildEcho(req Request, p Persona, date time.Time) []byte {
	hdrName, hdr, bodyName := "req-hdr", req.ReqHdr, "req-body"
	if req.Method == MethodRespmod {
		hdrName, hdr, bodyName = "res-hdr", req.ResHdr, "res-body"
	}
	var enc []string
	if len(hdr) > 0 {
		enc = append(enc, hdrName+"=0")
	}
	if req.HasBody() {
		enc = append(enc, fmt.Sprintf("%s=%d", bodyName, len(hdr)))
	} else {
		enc = append(enc, fmt.Sprintf("null-body=%d", len(hdr)))
	}

	var b builder
	b.status(200)
	b.common(p, date)
	b.header("Encapsulated", strings.Join(enc, ", "))
	b.WriteString("\r\n")
	b.Write(hdr)
	if req.HasBody() {
		if len(req.Body) > 0 {
			fmt.Fprintf(&b, "%x\r\n", len(req.Body))
			b.Write(req.Body)
			b.WriteString("\r\n")
		}
		b.WriteString("0\r\n\r\n")
	}
	return b.Bytes()
}
