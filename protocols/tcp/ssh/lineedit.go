package ssh

// MaxLine bounds one input line; further bytes are dropped and the line is
// marked truncated.
const MaxLine = 4096

// LineEditor turns the bytes a terminal sends into lines, handling the few
// control keys a bot or a person types: Enter, Backspace, Ctrl-C, Ctrl-D and
// escape sequences (arrow keys), which are swallowed.
type LineEditor struct {
	buf       []byte
	esc       int
	lastCR    bool
	truncated bool
}

// Key is the effect of one input byte.
type Key struct {
	Echo      []byte // what a pty should echo back
	Line      string // the finished line, when Done
	Done      bool   // a line was completed (Enter)
	EOF       bool   // Ctrl-D on an empty line
	Truncated bool   // Done line exceeded MaxLine
}

// Feed consumes one byte.
func (e *LineEditor) Feed(b byte) Key {
	if e.esc > 0 {
		e.esc--
		return Key{}
	}
	crlf := e.lastCR && b == '\n'
	e.lastCR = b == '\r'
	switch {
	case b == 0x1b:
		e.esc = 2
	case crlf:
	case b == '\r' || b == '\n':
		k := Key{Echo: []byte("\r\n"), Line: string(e.buf), Done: true, Truncated: e.truncated}
		e.buf, e.truncated = e.buf[:0], false
		return k
	case b == 0x7f || b == 0x08:
		if len(e.buf) > 0 {
			e.buf = e.buf[:len(e.buf)-1]
			return Key{Echo: []byte("\b \b")}
		}
	case b == 0x03:
		e.buf, e.truncated = e.buf[:0], false
		return Key{Echo: []byte("^C\r\n"), Done: true}
	case b == 0x04:
		if len(e.buf) == 0 {
			return Key{EOF: true}
		}
	case b >= 0x20:
		if len(e.buf) >= MaxLine {
			e.truncated = true
			return Key{}
		}
		e.buf = append(e.buf, b)
		return Key{Echo: []byte{b}}
	}
	return Key{}
}
