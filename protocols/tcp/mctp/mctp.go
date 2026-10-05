// Package mctp parses and builds MCTP/1.0, the text-framed control protocol
// spoken on tcp/9000 by HiSilicon-SDK DVRs (Kguard and many white-label
// recorders). Requests call `HI_SRDK_*` SDK functions, e.g.
//
//	REMOTE HI_SRDK_DEV_GetHddInfo MCTP/1.0\r\n
//	CSeq:173\r\n
//	Content-Length:15\r\n
//	\r\n
//	Segment-Num:0\r\n
//
// The body carries Segment-Num, then per segment Segment-Seq, Data-Length, a
// blank line, and Data-Length bytes of binary data. Format from the 2015
// Kguard DVR advisory (seclists.org/bugtraq/2015/Mar/34) and mushorg/glutton#73.
package mctp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// MethodRemote is the only request method seen in the wild.
	MethodRemote = "REMOTE"

	maxHeaders  = 64
	maxSegments = 64
	// maxDiscard bounds how many oversize body bytes are skipped to stay in sync.
	maxDiscard = 1 << 20
)

var (
	ErrMalformed    = errors.New("malformed MCTP request")
	ErrLineTooLong  = errors.New("MCTP line too long")
	ErrBodyTooLarge = errors.New("MCTP body too large")
)

// Segment is one data segment of a request body.
type Segment struct {
	Seq  int
	Data []byte
}

// Request is a parsed MCTP request.
type Request struct {
	Method        string
	Function      string
	Version       string
	Headers       map[string]string // keys lower-cased
	ContentLength int
	Body          []byte
	Segments      []Segment
}

// Header returns a header value by case-insensitive name.
func (r Request) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// LooksLikeMCTP reports whether the first bytes of a stream start an MCTP request.
func LooksLikeMCTP(snip []byte) bool {
	return bytes.HasPrefix(snip, []byte(MethodRemote+" "))
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
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "MCTP/") {
		return req, buf.Bytes(), false, fmt.Errorf("%w: request line %q", ErrMalformed, line)
	}
	req.Method, req.Function, req.Version = parts[0], parts[1], parts[2]
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
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return req, buf.Bytes(), false, fmt.Errorf("%w: header %q", ErrMalformed, line)
		}
		req.Headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
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
	req.Segments = parseSegments(req.Body)
	return req, buf.Bytes(), truncated, nil
}

// parseSegments decodes the segmented body best-effort and returns the
// segments that parsed cleanly.
func parseSegments(body []byte) []Segment {
	next := func() (string, bool) {
		i := bytes.IndexByte(body, '\n')
		if i < 0 {
			return "", false
		}
		line := strings.TrimRight(string(body[:i]), "\r")
		body = body[i+1:]
		return line, true
	}
	field := func(name string) (int, bool) {
		line, ok := next()
		if !ok {
			return 0, false
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			return 0, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		return n, err == nil && n >= 0
	}

	count, ok := field("Segment-Num")
	if !ok {
		return nil
	}
	var segments []Segment
	for i := 0; i < min(count, maxSegments); i++ {
		seq, ok := field("Segment-Seq")
		if !ok {
			break
		}
		length, ok := field("Data-Length")
		if !ok {
			break
		}
		if blank, ok := next(); !ok || blank != "" || length > len(body) {
			break
		}
		segments = append(segments, Segment{Seq: seq, Data: body[:length]})
		body = body[length:]
	}
	return segments
}

// BuildResponse returns a success reply with no data segments, echoing cseq.
func BuildResponse(cseq string, returnCode int) []byte {
	const body = "Segment-Num:0\r\n"
	return []byte("MCTP/1.0 200 OK\r\n" +
		"Content-Type:text/HDP\r\n" +
		"CSeq:" + cseq + "\r\n" +
		"Return-Code:" + strconv.Itoa(returnCode) + "\r\n" +
		"Content-Length:" + strconv.Itoa(len(body)) + "\r\n" +
		"\r\n" +
		body)
}
