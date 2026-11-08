package tcp

import (
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

// Mirai's echo loader writes a small downloader ("dlr") into a file 32 bytes
// per line (`/bin/busybox echo -ne "\x7f\x45…" >> .d`), then runs it with
// `chmod +x .d; ./.d`. The handler rebuilds those files so the binaries can be
// stored as samples, and merges consecutive appends into one read frame so a
// multi-architecture loader (hundreds of lines) does not use up maxTelnetFrames.
const (
	// maxTelnetEchoFile caps the bytes kept for one echo-written file.
	maxTelnetEchoFile = 1 << 20
	// maxTelnetEchoTotal caps the bytes kept across all files of a connection.
	maxTelnetEchoTotal = 4 << 20
	// maxTelnetEchoFrame caps the raw lines merged into one read frame.
	maxTelnetEchoFrame = 256 << 10
)

// telnetStoreSample stores a rebuilt file; tests swap it.
var telnetStoreSample = helpers.Store

// telnetEchoWrite is one `echo -e … > FILE` or `>> FILE` shell line.
type telnetEchoWrite struct {
	file   string
	data   []byte
	append bool
}

// telnetFile is a file the client built with echo on this connection.
type telnetFile struct {
	data      []byte
	frame     int    // index of the last read frame that wrote to it
	stored    string // hash of the content last passed to the store
	truncated bool
}

type shellToken struct {
	text string
	op   bool // unquoted `>` or `>>`
}

// tokenizeShellLine splits a simple shell line into words with POSIX quoting.
// It reports false for anything beyond a single command with redirections
// (pipes, `;`, `&`, substitutions), which are not handled as file writes.
func tokenizeShellLine(line string) ([]shellToken, bool) {
	var toks []shellToken
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			toks = append(toks, shellToken{text: cur.String()})
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
		case c == '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, false
			}
			cur.WriteString(line[i+1 : i+1+end])
			inWord = true
			i += end + 1
		case c == '"':
			inWord = true
			i++
			for ; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '`' || line[i] == '$' {
					return nil, false
				}
				// inside double quotes a backslash only escapes \ " $ `
				if line[i] == '\\' && i+1 < len(line) && strings.IndexByte("\\\"$`", line[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(line[i])
			}
			if i >= len(line) {
				return nil, false
			}
		case c == '\\':
			if i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				inWord = true
			}
		case c == '>':
			flush()
			op := ">"
			if i+1 < len(line) && line[i+1] == '>' {
				op = ">>"
				i++
			}
			toks = append(toks, shellToken{text: op, op: true})
		case strings.IndexByte(";|&<`$(){}", c) >= 0:
			return nil, false
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return toks, true
}

// parseTelnetEcho recognises `[/bin/busybox ]echo -e[n] ARGS >[>] FILE`, the
// echo-loader line, and returns the bytes it writes. Only escape-interpreting
// echo (-e) counts: plain `echo > F` is a writable-directory probe.
func parseTelnetEcho(msg string) (telnetEchoWrite, bool) {
	toks, ok := tokenizeShellLine(strings.TrimSpace(trimTelnetLine(msg)))
	if !ok || len(toks) < 3 {
		return telnetEchoWrite{}, false
	}
	if toks[0].text == "/bin/busybox" || toks[0].text == "busybox" {
		toks = toks[1:]
	}
	n := len(toks)
	if n < 3 || toks[0].op || (toks[0].text != "echo" && toks[0].text != "/bin/echo") {
		return telnetEchoWrite{}, false
	}
	redir, file := toks[n-2], toks[n-1]
	if !redir.op || file.op || file.text == "" {
		return telnetEchoWrite{}, false
	}
	args := toks[1 : n-2]
	newline, escapes := true, false
	for len(args) > 0 && isEchoFlag(args[0].text) {
		for _, f := range args[0].text[1:] {
			switch f {
			case 'n':
				newline = false
			case 'e':
				escapes = true
			case 'E':
				escapes = false
			}
		}
		args = args[1:]
	}
	if !escapes {
		return telnetEchoWrite{}, false
	}
	var out []byte
	for i, a := range args {
		if a.op {
			return telnetEchoWrite{}, false
		}
		if i > 0 {
			out = append(out, ' ')
		}
		var stop bool
		out, stop = appendEchoEscapes(out, a.text)
		if stop {
			newline = false
			break
		}
	}
	if newline {
		out = append(out, '\n')
	}
	return telnetEchoWrite{file: telnetFileName(file.text), data: out, append: redir.text == ">>"}, true
}

func isEchoFlag(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	for _, c := range s[1:] {
		if c != 'n' && c != 'e' && c != 'E' {
			return false
		}
	}
	return true
}

// appendEchoEscapes decodes BusyBox `echo -e` escapes. stop is true after \c,
// which ends all output.
func appendEchoEscapes(out []byte, s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out = append(out, s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case 'x':
			j := i + 1
			for j < len(s) && j < i+3 && isHexDigit(s[j]) {
				j++
			}
			if j == i+1 {
				out = append(out, '\\', 'x')
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:j], 16, 8)
			out = append(out, byte(v))
			i = j - 1
		case '0':
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint("0"+s[i+1:j], 8, 16)
			out = append(out, byte(v))
			i = j - 1
		case 'c':
			return out, true
		case 'a':
			out = append(out, '\a')
		case 'b':
			out = append(out, '\b')
		case 'e':
			out = append(out, 0x1b)
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case '\\':
			out = append(out, '\\')
		default:
			out = append(out, '\\', c)
		}
	}
	return out, false
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// telnetFileName keys files as the client named them, without a leading "./".
func telnetFileName(name string) string {
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return name
}

// telnetRunTargets returns the files a line makes executable or runs:
// `chmod … F`, `./F`, `sh F`, each optionally behind `/bin/busybox`.
func telnetRunTargets(msg string) []string {
	line := trimTelnetLine(msg)
	var out []string
	for _, seg := range strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' }) {
		f := strings.Fields(seg)
		if len(f) > 0 && (f[0] == "/bin/busybox" || f[0] == "busybox") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "chmod":
			for _, a := range f[1:] {
				if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") && !isOctalMode(a) {
					out = append(out, telnetFileName(a))
				}
			}
		case f[0] == "sh" || f[0] == "ash":
			if len(f) > 1 {
				out = append(out, telnetFileName(f[1]))
			}
		case strings.HasPrefix(f[0], "./") || strings.HasPrefix(f[0], "/"):
			out = append(out, telnetFileName(f[0]))
		}
	}
	return out
}

func isOctalMode(s string) bool {
	for _, c := range s {
		if c < '0' || c > '7' {
			return false
		}
	}
	return s != ""
}

// handleEchoLine applies an echo-loader line to the file map. The line's read
// frame is the last event; a `>>` append to the file the previous echo line
// wrote, with only a prompt between them, is merged into that line's frame.
// merged reports that, so the caller sends the prompt without recording it.
func (s *telnetServer) handleEchoLine(msg string) (merged bool) {
	w, ok := parseTelnetEcho(msg)
	readIdx := len(s.events) - 1
	if !ok || readIdx < 0 || s.events[readIdx].Direction != "read" || s.events[readIdx].Message != msg {
		s.echoFrame = -1
		return false
	}
	frame := readIdx
	if w.append && w.file == s.echoFile && s.echoFrame >= 0 && s.echoFrame == readIdx-2 &&
		s.events[readIdx-1].Direction == "write" && isTelnetPrompt(s.events[readIdx-1].Message) &&
		len(s.events[s.echoFrame].Message)+len(msg) <= maxTelnetEchoFrame {
		prev := &s.events[s.echoFrame]
		prev.Message += msg
		prev.Lines++
		prev.Truncated = prev.Truncated || s.events[readIdx].Truncated
		s.events = s.events[:readIdx]
		frame, merged = s.echoFrame, true
	} else {
		s.events[frame].Path = w.file
		s.events[frame].Lines = 1
	}

	f := s.files[w.file]
	if f == nil || !w.append {
		if f != nil {
			s.fileBytes -= len(f.data)
		}
		f = &telnetFile{}
		s.files[w.file] = f
	}
	keep := min(len(w.data), maxTelnetEchoFile-len(f.data), maxTelnetEchoTotal-s.fileBytes)
	keep = max(keep, 0)
	if keep < len(w.data) {
		f.truncated = true
		s.events[frame].Truncated = true
	}
	f.data = append(f.data, w.data[:keep]...)
	s.fileBytes += keep
	f.frame = frame
	s.echoFrame, s.echoFile = frame, w.file
	return merged
}

func isTelnetPrompt(msg string) bool {
	return msg == telnetPrompt || msg == telnetShPrompt
}

// storeRunTargets stores the echo-built files the line at readIdx runs or
// makes executable, and points that frame at the first of them.
func (s *telnetServer) storeRunTargets(msg string, readIdx int, logger interfaces.Logger) {
	if readIdx < 0 {
		return
	}
	for _, name := range telnetRunTargets(msg) {
		f := s.files[name]
		if f == nil || len(f.data) == 0 {
			continue
		}
		hash := s.storeFile(name, f, logger)
		if hash == "" {
			continue
		}
		ev := &s.events[readIdx]
		if ev.Path == "" && ev.PayloadHash == "" {
			ev.Path, ev.PayloadHash = name, hash
		}
	}
}

// storeEchoFiles stores files that were written but never run, at session end,
// and records the hash on each file's last echo frame.
func (s *telnetServer) storeEchoFiles(logger interfaces.Logger) {
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		f := s.files[name]
		if len(f.data) == 0 {
			continue
		}
		hash := s.storeFile(name, f, logger)
		if hash != "" && f.frame < len(s.events) && s.events[f.frame].PayloadHash == "" {
			s.events[f.frame].PayloadHash = hash
		}
	}
}

// storeFile stores f's current content once and returns its hash.
func (s *telnetServer) storeFile(name string, f *telnetFile, logger interfaces.Logger) string {
	hash := helpers.SHA256Hex(f.data)
	if f.stored == hash {
		return hash
	}
	f.stored = hash
	if s.storedHashes[hash] {
		return hash
	}
	s.storedHashes[hash] = true
	if _, err := telnetStoreSample(f.data, "samples"); err != nil {
		logger.Error("Failed to store echo-written file", slog.String("protocol", "telnet"), slog.String("path", name), producer.ErrAttr(err))
		return hash
	}
	logger.Info("New sample rebuilt from echo",
		slog.String("handler", "telnet"),
		slog.String("sample_hash", hash),
		slog.String("path", name),
		slog.Int("bytes", len(f.data)),
		slog.Bool("truncated", f.truncated),
	)
	return hash
}
