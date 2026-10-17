package sip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	// maxStreamHeader bounds the start line and headers of a stream message.
	maxStreamHeader = 8192
	// maxContentLength is the largest Content-Length a stream message may
	// declare; larger values are treated as a framing error rather than
	// read (and discarded) to the end.
	maxContentLength = 65536
)

var (
	// ErrHeaderTooLarge is returned when no empty line ends the headers
	// within maxStreamHeader bytes.
	ErrHeaderTooLarge = errors.New("sip: stream message header too large")
	// ErrContentLength is returned for a Content-Length that is not a number
	// or exceeds maxContentLength.
	ErrContentLength = errors.New("sip: invalid Content-Length")
)

// StreamMessage is one message read off a stream transport (TCP, TLS).
type StreamMessage struct {
	// Raw is the message as received: start line, headers, empty line and
	// the kept body. For a keepalive it is the CR/LF bytes.
	Raw []byte
	// Keepalive is set for a CRLF keepalive ping (RFC 5626 §4.4.1) instead
	// of a message; the peer expects a single CRLF back for "\r\n\r\n".
	Keepalive bool
	// Truncated is set when the body was longer than maxBody; the rest was
	// read and dropped, so the next message starts in the right place.
	Truncated bool
}

// ReadStreamMessage reads the next SIP message from r, framed by its
// Content-Length (RFC 3261 §18.3; a missing header means no body). Header
// lines may end in CRLF or a bare LF, and "l" is accepted as the compact
// form of Content-Length. Leading CR/LF bytes are returned on their own as a
// keepalive. On an error, Raw holds whatever was read of the message.
func ReadStreamMessage(r *bufio.Reader, maxBody int) (StreamMessage, error) {
	first, err := r.Peek(1)
	if err != nil {
		return StreamMessage{}, err
	}
	if first[0] == '\r' || first[0] == '\n' {
		return StreamMessage{Raw: readKeepalive(r), Keepalive: true}, nil
	}

	var raw []byte
	length := 0
	// lineStart is where the current line begins in raw; a line longer than
	// r's buffer arrives in several pieces
	lineStart := 0
	for {
		piece, err := r.ReadSlice('\n')
		raw = append(raw, piece...)
		if len(raw) > maxStreamHeader {
			return StreamMessage{Raw: raw}, ErrHeaderTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return StreamMessage{Raw: raw}, err
		}
		header := bytes.TrimRight(raw[lineStart:], "\r\n")
		lineStart = len(raw)
		if len(header) == 0 {
			break
		}
		name, value, ok := bytes.Cut(header, []byte(":"))
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(string(name))) {
		case "content-length", "l":
			n, err := strconv.Atoi(strings.TrimSpace(string(value)))
			if err != nil || n < 0 || n > maxContentLength {
				return StreamMessage{Raw: raw}, ErrContentLength
			}
			length = n
		}
	}

	keep := min(length, max(maxBody, 0))
	body := make([]byte, keep)
	n, err := io.ReadFull(r, body)
	raw = append(raw, body[:n]...)
	if err != nil {
		return StreamMessage{Raw: raw}, err
	}
	if rest := length - keep; rest > 0 {
		if _, err := r.Discard(rest); err != nil {
			return StreamMessage{Raw: raw, Truncated: true}, err
		}
	}
	return StreamMessage{Raw: raw, Truncated: length > keep}, nil
}

// readKeepalive consumes the run of CR/LF bytes at the head of r, waiting
// only for the first one.
func readKeepalive(r *bufio.Reader) []byte {
	var raw []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return raw
		}
		if c != '\r' && c != '\n' {
			_ = r.UnreadByte()
			return raw
		}
		raw = append(raw, c)
		if r.Buffered() == 0 {
			return raw
		}
	}
}
