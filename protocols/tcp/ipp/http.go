package ipp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxHeaders = 64
	// maxChunkSizeHex bounds the hex digits of a chunk size.
	maxChunkSizeHex = 15
	// maxDiscard bounds how many oversize body bytes are skipped to stay in sync.
	maxDiscard = 16 << 20
)

var (
	ErrLineTooLong  = errors.New("HTTP line too long")
	ErrBodyTooLarge = errors.New("HTTP body too large")
)

// Request is the head of an HTTP request carrying IPP (or a CUPS web page fetch).
type Request struct {
	Method  string
	URI     string
	Path    string
	Version string
	Headers map[string]string // keys lower-cased
	// ContentLength is -1 when the header is absent.
	ContentLength int64
	Chunked       bool
}

// Header returns a header value by case-insensitive name.
func (r Request) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// HasBody reports whether a body follows the head.
func (r Request) HasBody() bool {
	return r.Chunked || r.ContentLength > 0
}

// ExpectsContinue reports whether the client waits for 100 Continue.
func (r Request) ExpectsContinue() bool {
	return strings.EqualFold(r.Header("Expect"), "100-continue") && r.HasBody()
}

// KeepAlive reports whether the connection stays open after the response.
func (r Request) KeepAlive() bool {
	conn := strings.ToLower(r.Header("Connection"))
	if r.Version == "HTTP/1.0" {
		return strings.Contains(conn, "keep-alive")
	}
	return !strings.Contains(conn, "close")
}

// IsIPP reports whether the body is an IPP message.
func (r Request) IsIPP() bool {
	ct, _, _ := strings.Cut(r.Header("Content-Type"), ";")
	return strings.EqualFold(strings.TrimSpace(ct), "application/ipp")
}

// BasicAuth returns the credentials of an Authorization: Basic header.
func (r Request) BasicAuth() (username, password string, ok bool) {
	scheme, cred, found := strings.Cut(r.Header("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", "", false
	}
	username, password, ok = strings.Cut(string(dec), ":")
	return username, password, ok
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

// ReadHead reads the request line and headers. raw holds every byte
// consumed even when err is non-nil. A clean EOF before the first byte
// returns io.EOF with empty raw.
func ReadHead(r *bufio.Reader) (req Request, raw []byte, err error) {
	rd := &reader{r: r}
	req.ContentLength = -1

	line, err := rd.line()
	if err != nil {
		return req, rd.raw.Bytes(), err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return req, rd.raw.Bytes(), fmt.Errorf("%w: request line %q", ErrMalformed, line)
	}
	req.Method, req.URI, req.Version = parts[0], parts[1], parts[2]
	req.Path = req.URI
	if u, err := url.ParseRequestURI(req.URI); err == nil {
		req.Path = u.Path
	}
	req.Headers = map[string]string{}

	for i := 0; ; i++ {
		if i > maxHeaders {
			return req, rd.raw.Bytes(), fmt.Errorf("%w: too many headers", ErrMalformed)
		}
		line, err := rd.lineInBody()
		if err != nil {
			return req, rd.raw.Bytes(), err
		}
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return req, rd.raw.Bytes(), fmt.Errorf("%w: header %q", ErrMalformed, line)
		}
		req.Headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	if strings.Contains(strings.ToLower(req.Header("Transfer-Encoding")), "chunked") {
		req.Chunked = true
	} else if cl := req.Header("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return req, rd.raw.Bytes(), fmt.Errorf("%w: Content-Length %q", ErrMalformed, cl)
		}
		req.ContentLength = n
	}
	return req, rd.raw.Bytes(), nil
}

// ReadBody reads the body announced by req, keeping at most maxBody bytes.
// raw holds the wire bytes kept (chunk framing included); truncated is set
// when body bytes past maxBody were discarded.
func ReadBody(r *bufio.Reader, req Request, maxBody int) (body, raw []byte, truncated bool, err error) {
	rd := &reader{r: r}
	if req.Chunked {
		body, truncated, err = rd.chunked(maxBody)
		return body, rd.raw.Bytes(), truncated, err
	}
	if req.ContentLength <= 0 {
		return nil, nil, false, nil
	}
	keep := min(req.ContentLength, int64(maxBody))
	rest := req.ContentLength - keep
	if rest > maxDiscard {
		return nil, nil, true, ErrBodyTooLarge
	}
	body = make([]byte, keep)
	n, err := io.ReadFull(r, body)
	body = body[:n]
	if err == nil && rest > 0 {
		truncated = true
		_, err = io.CopyN(io.Discard, r, rest)
	}
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return body, body, truncated, err
}

// chunked reads a chunked body up to the zero-size chunk and its trailers.
func (rd *reader) chunked(maxBody int) (body []byte, truncated bool, err error) {
	discarded := int64(0)
	for {
		line, err := rd.lineInBody()
		if err != nil {
			return body, truncated, err
		}
		sizeStr, _, _ := strings.Cut(line, ";")
		sizeStr = strings.TrimSpace(sizeStr)
		if sizeStr == "" || len(sizeStr) > maxChunkSizeHex {
			return body, truncated, fmt.Errorf("%w: chunk size %q", ErrMalformed, line)
		}
		size, err := strconv.ParseUint(sizeStr, 16, 63)
		if err != nil {
			return body, truncated, fmt.Errorf("%w: chunk size %q", ErrMalformed, line)
		}
		if size == 0 {
			// trailers, then the blank line ending the body
			for i := 0; ; i++ {
				if i > maxHeaders {
					return body, truncated, fmt.Errorf("%w: too many trailers", ErrMalformed)
				}
				line, err := rd.lineInBody()
				if err != nil {
					return body, truncated, err
				}
				if line == "" {
					return body, truncated, nil
				}
			}
		}
		keep := int(min(size, uint64(maxBody-len(body))))
		rest := int64(size) - int64(keep)
		if rest > 0 {
			truncated = true
			if discarded+rest > maxDiscard {
				return body, truncated, ErrBodyTooLarge
			}
		}
		data := make([]byte, keep)
		n, err := io.ReadFull(rd.r, data)
		rd.raw.Write(data[:n])
		body = append(body, data[:n]...)
		if err == nil && rest > 0 {
			var skipped int64
			skipped, err = io.CopyN(io.Discard, rd.r, rest)
			discarded += skipped
		}
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return body, truncated, err
		}
		end, err := rd.lineInBody()
		if err != nil {
			return body, truncated, err
		}
		if end != "" {
			return body, truncated, fmt.Errorf("%w: missing CRLF after chunk", ErrMalformed)
		}
	}
}
