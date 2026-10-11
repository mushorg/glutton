// Package redis reads Redis client commands (RESP multibulk arrays and inline
// commands, https://redis.io/docs/latest/develop/reference/protocol-spec/)
// and builds RESP2 replies.
package redis

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
	// MaxRequestLen caps one command on the wire; it is the server's
	// PROTO_INLINE_MAX_SIZE and well above any cron or SSH-key payload.
	MaxRequestLen = 64 * 1024
	// MaxArgs caps the multibulk element count.
	MaxArgs = 1024
	// PeekLen covers "*N\r\n$" of the shortest multibulk request.
	PeekLen = 5
)

// ErrTooLong is returned when a command would pass the read cap.
var ErrTooLong = errors.New("redis command exceeds cap")

// ProtocolError is a malformed request. A real server replies with
// "-ERR Protocol error: <Msg>" and closes the connection.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "redis protocol error: " + e.Msg }

// Command is one client request.
type Command struct {
	Raw    []byte   // the request as read, framing included
	Args   [][]byte // command name first
	Inline bool     // sent as a plain text line instead of a RESP array
}

// Name returns the lowercased command name, or "" for an empty request.
func (c Command) Name() string {
	if len(c.Args) == 0 {
		return ""
	}
	return strings.ToLower(string(c.Args[0]))
}

// reader accumulates the raw bytes of a command while enforcing the cap.
type reader struct {
	r   *bufio.Reader
	raw []byte
	max int
}

func (r *reader) line() ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.r.ReadSlice('\n')
		if len(r.raw)+len(line)+len(chunk) > r.max {
			keep := r.max - len(r.raw) - len(line)
			line = append(line, chunk[:max(keep, 0)]...)
			r.raw = append(r.raw, line...)
			return nil, ErrTooLong
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		r.raw = append(r.raw, line...)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")), nil
	}
}

func (r *reader) full(n int) ([]byte, error) {
	tooLong := len(r.raw)+n > r.max
	if tooLong {
		n = r.max - len(r.raw)
	}
	b := make([]byte, n)
	got, err := io.ReadFull(r.r, b)
	r.raw = append(r.raw, b[:got]...)
	if err != nil {
		if errors.Is(err, io.EOF) && got > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if tooLong {
		return nil, ErrTooLong
	}
	return b, nil
}

// ReadCommand reads one request from r. A request that starts with '*' is a
// RESP multibulk array; anything else is an inline command line. Raw holds
// the bytes read so far even when an error is returned.
func ReadCommand(r *bufio.Reader, maxLen int) (Command, error) {
	rd := &reader{r: r, max: maxLen}
	first, err := r.Peek(1)
	if err != nil {
		return Command{}, err
	}
	if first[0] != '*' {
		line, err := rd.line()
		if err != nil {
			return Command{Raw: rd.raw, Inline: true}, err
		}
		args, err := SplitInline(line)
		return Command{Raw: rd.raw, Args: args, Inline: true}, err
	}
	return readMultibulk(rd)
}

func readMultibulk(rd *reader) (Command, error) {
	line, err := rd.line()
	if err != nil {
		return Command{Raw: rd.raw}, err
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return Command{Raw: rd.raw}, &ProtocolError{Msg: "invalid multibulk length"}
	}
	if n > MaxArgs {
		return Command{Raw: rd.raw}, ErrTooLong
	}
	// "*0" and "*-1" are empty requests the server skips
	cmd := Command{}
	for i := 0; i < n; i++ {
		line, err := rd.line()
		if err != nil {
			cmd.Raw = rd.raw
			return cmd, err
		}
		if len(line) == 0 || line[0] != '$' {
			cmd.Raw = rd.raw
			got := ""
			if len(line) > 0 {
				got = string(line[:1])
			}
			return cmd, &ProtocolError{Msg: fmt.Sprintf("expected '$', got '%s'", got)}
		}
		size, err := strconv.Atoi(string(line[1:]))
		// a bulk over the cap reads up to it and fails with ErrTooLong
		if err != nil || size < 0 {
			cmd.Raw = rd.raw
			return cmd, &ProtocolError{Msg: "invalid bulk length"}
		}
		body, err := rd.full(min(size, MaxRequestLen) + 2) // data + trailing \r\n
		if err != nil {
			cmd.Raw = rd.raw
			return cmd, err
		}
		cmd.Args = append(cmd.Args, body[:size])
	}
	cmd.Raw = rd.raw
	return cmd, nil
}

// SplitInline splits an inline command the way the server's sdssplitargs
// does: whitespace separated, with double-quoted (escapes \n \r \t \b \a
// \\ \" \xHH) and single-quoted (escape \') arguments.
func SplitInline(line []byte) ([][]byte, error) {
	var args [][]byte
	unbalanced := &ProtocolError{Msg: "unbalanced quotes in request"}
	i := 0
	for {
		for i < len(line) && isSpace(line[i]) {
			i++
		}
		if i == len(line) {
			return args, nil
		}
		var cur []byte
		inDQ, inSQ := false, false
		for done := false; !done; {
			if i == len(line) {
				if inDQ || inSQ {
					return nil, unbalanced
				}
				break
			}
			c := line[i]
			switch {
			case inDQ:
				switch {
				case c == '\\' && i+3 < len(line) && line[i+1] == 'x' && isHex(line[i+2]) && isHex(line[i+3]):
					v, _ := strconv.ParseUint(string(line[i+2:i+4]), 16, 8)
					cur = append(cur, byte(v))
					i += 3
				case c == '\\' && i+1 < len(line):
					i++
					cur = append(cur, unescape(line[i]))
				case c == '"':
					// the closing quote must be followed by a space or the end
					if i+1 < len(line) && !isSpace(line[i+1]) {
						return nil, unbalanced
					}
					done = true
				default:
					cur = append(cur, c)
				}
			case inSQ:
				switch {
				case c == '\\' && i+1 < len(line) && line[i+1] == '\'':
					i++
					cur = append(cur, '\'')
				case c == '\'':
					if i+1 < len(line) && !isSpace(line[i+1]) {
						return nil, unbalanced
					}
					done = true
				default:
					cur = append(cur, c)
				}
			default:
				switch {
				case isSpace(c):
					done = true
				case c == '"':
					inDQ = true
				case c == '\'':
					inSQ = true
				default:
					cur = append(cur, c)
				}
			}
			i++
		}
		if cur == nil {
			cur = []byte{}
		}
		args = append(args, cur)
	}
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'b':
		return '\b'
	case 'a':
		return '\a'
	}
	return c
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// LooksLikeRESP reports whether b starts a RESP multibulk request: "*N\r\n"
// followed by the "$" of the first bulk string.
func LooksLikeRESP(b []byte) bool {
	if len(b) < PeekLen || b[0] != '*' {
		return false
	}
	i := 1
	for i < len(b) && i <= 5 && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 1 || b[1] == '0' {
		return false
	}
	return bytes.HasPrefix(b[i:], []byte("\r\n$"))
}
