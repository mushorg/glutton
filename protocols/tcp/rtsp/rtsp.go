// Package rtsp parses RTSP/1.0 requests (RFC 2326) and builds the replies of
// an IP camera that wants credentials. Camera scanners open with
//
//	OPTIONS rtsp://192.0.2.1:554 RTSP/1.0\r\n
//	CSeq: 1\r\n
//	\r\n
//
// then DESCRIBE a stream path, get 401, and retry with Basic or Digest
// credentials. The persona is a Dahua-style "Rtsp Server/3.0".
package rtsp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the only protocol version answered with anything but 505.
const Version = "RTSP/1.0"

const (
	maxHeaders = 64
	// maxDiscard bounds how many oversize body bytes are skipped to stay in sync.
	maxDiscard = 1 << 20
	// maxCSeq bounds the CSeq echoed back; real ones are small counters.
	maxCSeq = 10
)

// Methods are the RFC 2326 request methods.
var Methods = []string{
	"OPTIONS", "DESCRIBE", "ANNOUNCE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
	"GET_PARAMETER", "SET_PARAMETER", "REDIRECT", "RECORD",
}

// public is the Public header of the OPTIONS reply.
const public = "OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, TEARDOWN, SET_PARAMETER, GET_PARAMETER"

var (
	ErrMalformed    = errors.New("malformed RTSP request")
	ErrLineTooLong  = errors.New("RTSP line too long")
	ErrBodyTooLarge = errors.New("RTSP body too large")
)

// Request is a parsed RTSP request.
type Request struct {
	Method        string
	URI           string
	Version       string
	Headers       map[string]string // keys lower-cased
	ContentLength int
	Body          []byte
}

// Header returns a header value by case-insensitive name.
func (r Request) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// Path returns the path of the request URI, "/" for a bare rtsp://host:port,
// and the raw URI when it is not absolute (e.g. "*").
func (r Request) Path() string {
	u, err := url.Parse(r.URI)
	if err != nil || u.Host == "" {
		return r.URI
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// URIUsername returns the user name embedded in the request URI
// (rtsp://admin:pass@host/...), which some brute-forcers use instead of an
// Authorization header.
func (r Request) URIUsername() string {
	u, err := url.Parse(r.URI)
	if err != nil || u.User == nil {
		return ""
	}
	return u.User.Username()
}

// MayStart reports whether snip (the first bytes of a stream) could begin an
// RTSP request line.
func MayStart(snip []byte) bool {
	if len(snip) == 0 {
		return false
	}
	for _, m := range Methods {
		n := min(len(snip), len(m)+1)
		if bytes.Equal(snip[:n], []byte(m + " ")[:n]) {
			return true
		}
	}
	return false
}

// LooksLikeRTSP reports whether b starts with an RTSP request line: a known
// method followed by an RTSP/x.y version, or by an rtsp:// URI when the line
// is longer than b.
func LooksLikeRTSP(b []byte) bool {
	line, complete := b, false
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line, complete = b[:i], true
	}
	parts := strings.Fields(string(line))
	if len(parts) < 2 || !isMethod(parts[0]) {
		return false
	}
	if len(parts) == 3 && strings.HasPrefix(parts[2], "RTSP/") {
		return true
	}
	uri := strings.ToLower(parts[1])
	return !complete && len(parts) == 2 && (strings.HasPrefix(uri, "rtsp://") || strings.HasPrefix(uri, "rtsps://"))
}

func isMethod(s string) bool {
	for _, m := range Methods {
		if s == m {
			return true
		}
	}
	return false
}

// ReadRequest reads one request from r. raw holds every byte consumed (the
// wire request, capped at maxBody for the body) even when err is non-nil.
// truncated is set when the body exceeded maxBody. A clean EOF before the
// first byte returns io.EOF with empty raw.
func ReadRequest(r *bufio.Reader, maxBody int) (req Request, raw []byte, truncated bool, err error) {
	var buf bytes.Buffer
	readLine := func() (string, error) {
		line, err := r.ReadSlice('\n')
		buf.Write(line)
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

	line, err := readLine()
	if err != nil {
		return req, buf.Bytes(), false, err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "RTSP/") {
		return req, buf.Bytes(), false, fmt.Errorf("%w: request line %q", ErrMalformed, line)
	}
	req.Method, req.URI, req.Version = parts[0], parts[1], parts[2]
	req.Headers = map[string]string{}

	for i := 0; ; i++ {
		if i > maxHeaders {
			return req, buf.Bytes(), false, fmt.Errorf("%w: too many headers", ErrMalformed)
		}
		line, err := readLine()
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return req, buf.Bytes(), false, err
		}
		if line == "" {
			break
		}
		// clients are not strict about headers; skip lines without a colon
		if key, value, ok := strings.Cut(line, ":"); ok {
			req.Headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}

	if cl := req.Header("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 {
			return req, buf.Bytes(), false, fmt.Errorf("%w: Content-Length %q", ErrMalformed, cl)
		}
		req.ContentLength = n
	}

	keep := min(req.ContentLength, maxBody)
	rest := req.ContentLength - keep
	truncated = rest > 0
	if rest > maxDiscard {
		// do not wait for (or skip) megabytes the client may never send
		return req, buf.Bytes(), truncated, ErrBodyTooLarge
	}
	body := make([]byte, keep)
	n, err := io.ReadFull(r, body)
	buf.Write(body[:n])
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return req, buf.Bytes(), truncated, err
	}
	req.Body = body
	if rest > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(rest)); err != nil {
			return req, buf.Bytes(), truncated, err
		}
	}
	return req, buf.Bytes(), truncated, nil
}

// Auth is a parsed Authorization header. The Basic password is deliberately
// not kept.
type Auth struct {
	Scheme   string // "basic", "digest", or the lower-cased unknown scheme
	Username string
	Realm    string // digest only
	URI      string // digest only
	Response string // digest response hash
}

// ParseAuthorization parses a Basic or Digest Authorization value. An
// unknown scheme returns only the scheme.
func ParseAuthorization(value string) Auth {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
	auth := Auth{Scheme: strings.ToLower(scheme)}
	switch auth.Scheme {
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return auth
		}
		auth.Username, _, _ = strings.Cut(string(decoded), ":")
	case "digest":
		params := digestParams(rest)
		auth.Username = params["username"]
		auth.Realm = params["realm"]
		auth.URI = params["uri"]
		auth.Response = params["response"]
	}
	return auth
}

// digestParams splits comma-separated key=value pairs; quoted values may
// contain commas.
func digestParams(s string) map[string]string {
	params := map[string]string{}
	for s != "" {
		s = strings.TrimLeft(s, " \t,")
		key, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rest = strings.TrimLeft(rest, " \t")
		var value string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				value, s = rest[1:], ""
			} else {
				value, s = rest[1:1+end], rest[2+end:]
			}
		} else {
			value, s, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(value)
		}
		params[key] = value
	}
	return params
}

// Responder answers like a Dahua-style camera that demands credentials for
// every stream. Its fields are fixed per session so the challenge is stable.
type Responder struct {
	Server string
	Realm  string
	Nonce  string
	Now    func() time.Time
}

// NewResponder returns a responder with a fresh nonce and the given realm.
func NewResponder(realm string) *Responder {
	return &Responder{Server: "Rtsp Server/3.0", Realm: realm, Nonce: randomHex(16), Now: time.Now}
}

// RandomSerial returns a device serial in the style of Dahua realms
// ("Login to <serial>").
func RandomSerial() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "7K02D8APAZ1C3F9"
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "9d6c1f2b8e4a07c3d5f1a2b3c4d5e6f7"
	}
	return hex.EncodeToString(b)
}

// Reply returns the status code and wire bytes answering req. Nothing is
// ever authorized: stream methods get a 401 challenge, session methods 454.
func (r *Responder) Reply(req Request) (int, []byte) {
	cseq := req.Header("CSeq")
	if !validCSeq(cseq) {
		return 400, r.build(400, "", nil)
	}
	if req.Version != Version {
		return 505, r.build(505, cseq, nil)
	}
	switch req.Method {
	case "OPTIONS":
		return 200, r.build(200, cseq, [][2]string{{"Public", public}})
	case "DESCRIBE", "SETUP", "ANNOUNCE", "RECORD":
		return 401, r.build(401, cseq, [][2]string{
			{"WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s"`, r.Realm, r.Nonce)},
			{"WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, r.Realm)},
		})
	case "PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER":
		return 454, r.build(454, cseq, nil)
	default:
		return 501, r.build(501, cseq, nil)
	}
}

func validCSeq(s string) bool {
	if s == "" || len(s) > maxCSeq {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var reasons = map[int]string{
	200: "OK",
	400: "Bad Request",
	401: "Unauthorized",
	454: "Session Not Found",
	501: "Not Implemented",
	505: "RTSP Version Not Supported",
}

func (r *Responder) build(code int, cseq string, headers [][2]string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", Version, code, reasons[code])
	if cseq != "" {
		b.WriteString("CSeq: " + cseq + "\r\n")
	}
	b.WriteString("Date: " + r.Now().UTC().Format(http.TimeFormat) + "\r\n")
	b.WriteString("Server: " + r.Server + "\r\n")
	for _, h := range headers {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}
