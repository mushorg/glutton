package ssh

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Statuses of a Result.
const (
	StatusOK       = "ok"
	StatusNotFound = "not-found" // the command is not emulated
)

// Bounds on what one session can make the shell do.
const (
	// MaxFSBytes and MaxFSFiles cap the in-memory filesystem a client can fill.
	MaxFSBytes = 64 << 10
	MaxFSFiles = 64

	maxDepth  = 3        // nested sh -c, $(...) and script runs
	maxSteps  = 512      // commands run for one input line, nesting included
	maxOutput = 64 << 10 // output kept for one input line
)

// Shell is a fake bash session. It never touches the host: every answer is
// canned, files the client writes live in memory for the session, and
// downloaders (wget, curl, tftp) fail as if the network were down, so the
// honeypot does not fetch attacker-supplied URLs.
type Shell struct {
	persona Persona
	user    string
	cwd     string
	// Now is the clock for date, uptime and listings; tests replace it.
	Now func() time.Time

	baseDirs  map[string]string
	baseFiles map[string]string
	fs        *vfs

	writes []FileWrite
	budget int
}

// vfs is what the client changed: it overlays the canned directories and files.
type vfs struct {
	mu    sync.Mutex // held while a line runs: sessions of one connection share the filesystem
	files map[string]string
	dirs  map[string]bool
	gone  map[string]bool
	modes map[string]uint32
	bytes int
}

// FileWrite is one write to a file, as the client made it.
type FileWrite struct {
	Path   string // absolute
	Data   []byte // what this write added, not the whole file
	Append bool
}

// NewShell starts a session for user on persona.
func NewShell(p Persona, user string) *Shell {
	s := &Shell{persona: p, user: user, Now: time.Now}
	s.fs = &vfs{files: map[string]string{}, dirs: map[string]bool{}, gone: map[string]bool{}, modes: map[string]uint32{}}
	s.baseDirs = s.dirs()
	s.baseFiles = s.files()
	s.cwd = s.home()
	return s
}

// Session returns a shell for another session of the same connection: it has
// its own working directory and sees the same files.
func (s *Shell) Session() *Shell {
	c := *s
	c.cwd = c.home()
	c.writes = nil
	return &c
}

func (s *Shell) home() string {
	if s.user == "root" {
		return "/root"
	}
	return "/home/" + s.user
}

// Prompt returns the bash prompt for the current directory.
func (s *Shell) Prompt() string {
	dir := s.cwd
	if dir == s.home() {
		dir = "~"
	}
	sigil := "$"
	if s.user == "root" {
		sigil = "#"
	}
	host := s.persona.Hostname
	return fmt.Sprintf("%s@%s:%s%s ", s.user, host, dir, sigil)
}

// Result is the outcome of one input line.
type Result struct {
	Output string      // stdout and stderr, "\n" line ends
	Status string      // StatusOK, or StatusNotFound when the last command is unknown
	Code   int         // exit status of the last command
	Exit   bool        // the session ends (exit, logout)
	Writes []FileWrite // files the line wrote, in order
}

// outcome is the result of one simple command.
type outcome struct {
	out     string
	err     string
	code    int
	unknown bool // the command is not emulated
	exit    bool
	skip    bool // nothing ran (an empty command)
}

func fail(code int, format string, a ...any) outcome {
	return outcome{err: fmt.Sprintf(format, a...) + "\n", code: code}
}

// Run executes one input line. Commands joined with ;, && or || run as bash
// would, a pipeline runs only its first command, and sh -c, $(...) and
// redirections to files are followed.
func (s *Shell) Run(line string) Result {
	s.fs.mu.Lock()
	defer s.fs.mu.Unlock()
	s.writes = nil
	s.budget = maxSteps
	res := s.run(line, 0)
	res.Writes = s.writes
	return res
}

func (s *Shell) run(line string, depth int) Result {
	res := Result{Status: StatusOK}
	var out strings.Builder
	for _, seg := range splitCommands(line) {
		if (seg.op == "&&" && res.Code != 0) || (seg.op == "||" && res.Code == 0) {
			continue
		}
		if s.budget <= 0 {
			break
		}
		s.budget--
		o := s.command(seg.text, depth)
		if o.skip {
			continue
		}
		out.WriteString(o.out)
		out.WriteString(o.err)
		res.Code = o.code
		res.Status = StatusOK
		if o.unknown {
			res.Status = StatusNotFound
		}
		if o.exit {
			res.Exit = true
			break
		}
		if out.Len() > maxOutput {
			break
		}
	}
	res.Output = out.String()
	if len(res.Output) > maxOutput {
		res.Output = res.Output[:maxOutput]
	}
	return res
}

type segment struct {
	text string
	op   string // how it follows the previous one: ";", "&&" or "||"
}

// splitCommands splits on ;, newline, &, && and || outside quotes and
// substitutions, drops comments, joins backslash-newline continuations, and
// drops everything after the first | of each command.
func splitCommands(line string) []segment {
	var segs []segment
	var cur strings.Builder
	var quote rune
	op := ";"
	piped := false
	parens := 0
	ticks := false
	flush := func(next string) {
		if strings.TrimSpace(cur.String()) == "" {
			// an operator at the end of a line continues on the next one
			if next != ";" {
				op = next
			}
		} else {
			segs = append(segs, segment{cur.String(), op})
			op = next
		}
		cur.Reset()
		piped = false
	}
	runes := []rune(line)
	put := func(r rune) {
		if !piped {
			cur.WriteRune(r)
		}
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		var next rune
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		top := parens == 0 && !ticks
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else if c == '\\' && next != 0 {
				put(c)
				put(next)
				i++
				continue
			}
		case c == '\\' && next == '\n':
			i++
			continue
		case c == '\\' && next != 0:
			put(c)
			put(next)
			i++
			continue
		case c == '\'' || c == '"':
			quote = c
		case c == '$' && next == '(':
			parens++
			put(c)
			put(next)
			i++
			continue
		case c == ')' && parens > 0:
			parens--
		case c == '`':
			ticks = !ticks
		case c == '#' && top && (i == 0 || unicode.IsSpace(runes[i-1])):
			for i+1 < len(runes) && runes[i+1] != '\n' {
				i++
			}
			continue
		case top && (c == ';' || c == '\n'):
			flush(";")
			continue
		case top && c == '&' && next == '&':
			i++
			flush("&&")
			continue
		case top && c == '|' && next == '|':
			i++
			flush("||")
			continue
		case top && c == '&' && next != '>' && (i == 0 || runes[i-1] != '>'):
			flush(";")
			continue
		case top && c == '|':
			piped = true
		}
		put(c)
	}
	flush(";")
	return segs
}

type redirect struct {
	fd       int // 0 stdin, 1 stdout, 2 stderr, -1 both
	appendTo bool
	dup      bool // 2>&1: target is a descriptor number
	target   string
}

// closeParen returns the index of the ) that closes the ( at runes[open], or -1.
func closeParen(runes []rune, open int) int {
	depth := 0
	for i := open; i < len(runes); i++ {
		switch runes[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (s *Shell) subst(inner string, depth int) string {
	if depth >= maxDepth {
		return ""
	}
	return strings.TrimRight(s.run(inner, depth+1).Output, "\n")
}

// tokenize splits one simple command into words, removing quotes, expanding
// $(...) and `...`, and collecting redirections.
func (s *Shell) tokenize(text string, depth int) ([]string, []redirect) {
	var args []string
	var reds []redirect
	var cur strings.Builder
	started := false
	pending := -1
	word := func() {
		if !started {
			return
		}
		w := cur.String()
		cur.Reset()
		started = false
		if pending >= 0 {
			reds[pending].target = w
			pending = -1
			return
		}
		args = append(args, w)
	}
	put := func(r rune) {
		cur.WriteRune(r)
		started = true
	}
	runes := []rune(text)
	var quote rune
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		var next rune
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				put(c)
			}
			continue
		case quote == '"' && c == '"':
			quote = 0
			continue
		case quote == '"' && c == '\\' && next != 0 && strings.ContainsRune("\"\\$`", next):
			put(next)
			i++
			continue
		case c == '$' && next == '(':
			if end := closeParen(runes, i+1); end > 0 {
				cur.WriteString(s.subst(string(runes[i+2:end]), depth))
				started = true
				i = end
				continue
			}
		case c == '`':
			end := i + 1
			for end < len(runes) && runes[end] != '`' {
				end++
			}
			if end < len(runes) {
				cur.WriteString(s.subst(string(runes[i+1:end]), depth))
				started = true
				i = end
				continue
			}
		}
		if quote == '"' {
			put(c)
			continue
		}
		switch {
		case c == '\'' || c == '"':
			quote = c
			started = true
		case c == '\\' && next != 0:
			if next != '\n' {
				put(next)
			}
			i++
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			word()
		case c == '&' && next == '>':
			word()
			cur.WriteRune('&')
			started = true
		case c == '>' || c == '<':
			fd := 1
			if c == '<' {
				fd = 0
			}
			if started {
				switch cur.String() {
				case "1", "2":
					fd = int(cur.String()[0] - '0')
					cur.Reset()
					started = false
				case "&":
					fd = -1
					cur.Reset()
					started = false
				default:
					word()
				}
			}
			rd := redirect{fd: fd}
			if next == c {
				rd.appendTo = true
				i++
			}
			if c == '>' && i+2 < len(runes) && runes[i+1] == '&' && unicode.IsDigit(runes[i+2]) {
				rd.dup, rd.target = true, string(runes[i+2])
				i += 2
				reds = append(reds, rd)
				break
			}
			reds = append(reds, rd)
			pending = len(reds) - 1
		default:
			put(c)
		}
	}
	word()
	return args, reds
}

// wrappers run the command that follows them.
var wrappers = map[string]bool{"sudo": true, "nohup": true, "exec": true, "time": true}

// command runs one simple command.
func (s *Shell) command(text string, depth int) outcome {
	args, reds := s.tokenize(text, depth)
	for len(args) > 0 && wrappers[args[0]] {
		args = args[1:]
	}
	if len(args) == 0 && len(reds) == 0 {
		return outcome{skip: true}
	}
	var o outcome
	if len(args) > 0 {
		o = s.builtin(args[0], args[1:], depth)
	}
	return s.redirect(o, reds)
}

// redirect applies redirections to a finished command: stdout to a file (the
// in-memory one), stderr dropped or merged.
func (s *Shell) redirect(o outcome, reds []redirect) outcome {
	var file string
	appendTo, merge := false, false
	for _, rd := range reds {
		switch {
		case rd.fd == 0:
		case rd.dup && rd.fd == 2:
			merge = true
		case rd.dup:
		case rd.fd == 2:
			o.err = ""
		case rd.target == "":
		default:
			file, appendTo = rd.target, rd.appendTo
			if rd.fd == -1 {
				merge = true
			}
		}
	}
	if merge {
		o.out, o.err = o.out+o.err, ""
	}
	if file == "" {
		return o
	}
	data := o.out
	o.out = ""
	if file == "/dev/null" {
		return o
	}
	p := s.resolve(file)
	if reason := s.writeFile(p, data, appendTo); reason != "" {
		o.err += fmt.Sprintf("bash: %s: %s\n", file, reason)
		if o.code == 0 {
			o.code = 1
		}
		return o
	}
	if data != "" {
		s.writes = append(s.writes, FileWrite{Path: p, Data: []byte(data), Append: appendTo})
	}
	return o
}

func (s *Shell) builtin(name string, args []string, depth int) outcome {
	p := s.persona
	if strings.Contains(name, "/") {
		for _, dir := range []string{"/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/"} {
			if strings.HasPrefix(name, dir) && !strings.Contains(name[len(dir):], "/") {
				name = name[len(dir):]
				break
			}
		}
	}
	switch name {
	case "exit", "logout":
		code := 0
		if len(args) > 0 {
			code, _ = strconv.Atoi(args[0])
		}
		return outcome{out: "logout\n", code: code & 0xff, exit: true}
	case "whoami":
		return outcome{out: s.user + "\n"}
	case "id":
		if s.user == "root" {
			return outcome{out: "uid=0(root) gid=0(root) groups=0(root)\n"}
		}
		return outcome{out: fmt.Sprintf("uid=1000(%[1]s) gid=1000(%[1]s) groups=1000(%[1]s),27(sudo)\n", s.user)}
	case "pwd":
		return outcome{out: s.cwd + "\n"}
	case "hostname":
		return outcome{out: p.Hostname + "\n"}
	case "uname":
		return outcome{out: s.uname(args)}
	case "nproc":
		return outcome{out: fmt.Sprintf("%d\n", p.Cores)}
	case "date":
		return outcome{out: s.Now().UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n"}
	case "uptime":
		now := s.Now().UTC()
		return outcome{out: fmt.Sprintf(" %s up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n", now.Format("15:04:05"))}
	case "cd":
		return s.cd(args)
	case "ls", "dir":
		return s.ls(args)
	case "cat":
		return s.cat(args)
	case "echo":
		return outcome{out: echo(args)}
	case "mkdir":
		return s.mkdirCmd(args)
	case "touch":
		return s.touch(args)
	case "rm":
		return s.rm(args)
	case "chmod":
		return s.chmod(args)
	case "sh", "bash", "ash", "dash":
		return s.shellCmd(name, args, depth)
	case "ps":
		return outcome{out: "    PID TTY          TIME CMD\n   1042 pts/0    00:00:00 bash\n   1067 pts/0    00:00:00 ps\n"}
	case "history":
		return outcome{}
	case "crontab":
		return outcome{out: "no crontab for " + s.user + "\n"}
	case "free":
		return outcome{out: "               total        used        free      shared  buff/cache   available\nMem:         4025044      612340     2410288        1264      1002416     3207612\nSwap:              0           0           0\n"}
	case "wget":
		return outcome{err: "wget: unable to resolve host address\n", code: 4}
	case "curl":
		return outcome{err: "curl: (6) Could not resolve host\n", code: 6}
	case "tftp", "ftpget":
		return outcome{err: name + ": can't resolve host\n", code: 1}
	case "busybox":
		if len(args) > 0 {
			return outcome{err: args[0] + ": applet not found\n", code: 1}
		}
		return outcome{}
	case "false":
		return outcome{code: 1}
	case "export", "unset", "set", "unalias", "alias", "chown", "kill", "pkill", "killall", "sleep", "source", ".", ":",
		"ulimit", "umask", "clear", "setsid", "sync", "mv", "cp", "ln", "systemctl", "service", "iptables", "passwd",
		"chattr", "true":
		return outcome{}
	}
	if strings.Contains(name, "/") {
		return s.runPath(name, depth)
	}
	return outcome{err: fmt.Sprintf("bash: %s: command not found\n", name), code: 127, unknown: true}
}

// runPath runs a script the client wrote earlier, as ./x or /tmp/x does.
func (s *Shell) runPath(name string, depth int) outcome {
	p := s.resolve(name)
	if s.isDir(p) {
		return fail(126, "bash: %s: Is a directory", name)
	}
	body, ok := s.file(p)
	if !ok {
		return fail(127, "bash: %s: No such file or directory", name)
	}
	return s.subshell(body, depth)
}

// subshell runs a script in a nested shell: its exit does not end the session.
func (s *Shell) subshell(script string, depth int) outcome {
	if depth >= maxDepth {
		return fail(254, "bash: fork: retry: Resource temporarily unavailable")
	}
	r := s.run(script, depth+1)
	return outcome{out: r.Output, code: r.Code, unknown: r.Status == StatusNotFound}
}

// shellCmd runs sh, bash and friends: with -c a command string, otherwise a
// script file; with neither it reads a stdin that is empty.
func (s *Shell) shellCmd(name string, args []string, depth int) outcome {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c":
			if i+1 >= len(args) {
				return fail(2, "%s: -c: option requires an argument", name)
			}
			return s.subshell(args[i+1], depth)
		case strings.HasPrefix(a, "-"):
		default:
			body, ok := s.file(s.resolve(a))
			if !ok {
				return fail(127, "%s: 0: cannot open %s: No such file", name, a)
			}
			return s.subshell(body, depth)
		}
	}
	return outcome{}
}

func (s *Shell) uname(args []string) string {
	p := s.persona
	if len(args) == 0 {
		return "Linux\n"
	}
	var parts []string
	for _, a := range args {
		switch a {
		case "-a", "--all":
			return fmt.Sprintf("Linux %s %s %s x86_64 x86_64 x86_64 GNU/Linux\n", p.Hostname, p.Kernel, p.Build)
		case "-s":
			parts = append(parts, "Linux")
		case "-n":
			parts = append(parts, p.Hostname)
		case "-r":
			parts = append(parts, p.Kernel)
		case "-v":
			parts = append(parts, p.Build)
		case "-m", "-p", "-i":
			parts = append(parts, "x86_64")
		case "-o":
			parts = append(parts, "GNU/Linux")
		}
	}
	return strings.Join(parts, " ") + "\n"
}

// dirs maps the directories the shell starts with to their listing.
func (s *Shell) dirs() map[string]string {
	return map[string]string{
		"/":               "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
		"/root":           "",
		"/tmp":            "",
		"/etc":            "hostname  hosts  issue  os-release  passwd  resolv.conf  shadow  ssh",
		"/home":           s.user,
		"/home/" + s.user: "",
		"/var":            "backups  cache  lib  local  lock  log  mail  opt  run  spool  tmp",
		"/var/tmp":        "",
		"/usr":            "bin  games  include  lib  local  sbin  share  src",
	}
}

func (s *Shell) resolve(p string) string {
	switch {
	case p == "" || p == "~":
		return s.home()
	case strings.HasPrefix(p, "~/"):
		p = s.home() + p[1:]
	case !strings.HasPrefix(p, "/"):
		p = strings.TrimSuffix(s.cwd, "/") + "/" + p
	}
	var stack []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}
	return "/" + strings.Join(stack, "/")
}

func (s *Shell) isDir(p string) bool {
	if s.fs.gone[p] {
		return false
	}
	if s.fs.dirs[p] {
		return true
	}
	_, ok := s.baseDirs[p]
	return ok
}

// file returns the content of the regular file at p.
func (s *Shell) file(p string) (string, bool) {
	if s.fs.gone[p] {
		return "", false
	}
	if c, ok := s.fs.files[p]; ok {
		return c, true
	}
	c, ok := s.baseFiles[p]
	return c, ok
}

func (s *Shell) entries() int { return len(s.fs.files) + len(s.fs.dirs) }

// writeFile replaces or appends to the file at p and returns why it could not,
// or "".
func (s *Shell) writeFile(p, data string, appendTo bool) string {
	if s.isDir(p) {
		return "Is a directory"
	}
	if !s.isDir(path.Dir(p)) {
		return "No such file or directory"
	}
	content := data
	if old, ok := s.file(p); ok && appendTo {
		content = old + data
	}
	prev, inOverlay := s.fs.files[p]
	delta := len(content) - len(prev)
	if s.fs.bytes+delta > MaxFSBytes || (!inOverlay && s.entries() >= MaxFSFiles) {
		return "No space left on device"
	}
	s.fs.files[p] = content
	s.fs.bytes += delta
	delete(s.fs.gone, p)
	return ""
}

func (s *Shell) mkdir(p string, parents bool) string {
	if s.isDir(p) {
		if parents {
			return ""
		}
		return "File exists"
	}
	if _, ok := s.file(p); ok {
		return "File exists"
	}
	if parent := path.Dir(p); !s.isDir(parent) {
		if !parents {
			return "No such file or directory"
		}
		if reason := s.mkdir(parent, true); reason != "" {
			return reason
		}
	}
	if s.entries() >= MaxFSFiles {
		return "No space left on device"
	}
	s.fs.dirs[p] = true
	delete(s.fs.gone, p)
	return ""
}

func (s *Shell) mode(p string, dir bool) uint32 {
	if m, ok := s.fs.modes[p]; ok {
		return m
	}
	if dir {
		return 0o755
	}
	return 0o644
}

func (s *Shell) cd(args []string) outcome {
	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	dir := s.resolve(target)
	if s.isDir(dir) {
		s.cwd = dir
		return outcome{}
	}
	if _, ok := s.file(dir); ok {
		return fail(1, "bash: cd: %s: Not a directory", target)
	}
	return fail(1, "bash: cd: %s: No such file or directory", target)
}

type dirEntry struct {
	name string
	dir  bool
	size int
}

// list returns the entries of directory dir: the canned ones and the client's.
func (s *Shell) list(dir string) []dirEntry {
	seen := map[string]dirEntry{}
	for _, n := range strings.Fields(s.baseDirs[dir]) {
		child := path.Join(dir, n)
		if s.fs.gone[child] {
			continue
		}
		if c, ok := s.baseFiles[child]; ok {
			seen[n] = dirEntry{name: n, size: len(c)}
		} else {
			seen[n] = dirEntry{name: n, dir: true, size: 4096}
		}
	}
	for p, c := range s.fs.files {
		if path.Dir(p) == dir {
			seen[path.Base(p)] = dirEntry{name: path.Base(p), size: len(c)}
		}
	}
	for p := range s.fs.dirs {
		if path.Dir(p) == dir && p != dir {
			seen[path.Base(p)] = dirEntry{name: path.Base(p), dir: true, size: 4096}
		}
	}
	list := make([]dirEntry, 0, len(seen))
	for _, e := range seen {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	return list
}

func modeString(dir bool, m uint32) string {
	b := []byte("----------")
	if dir {
		b[0] = 'd'
	}
	for i, c := range "rwxrwxrwx" {
		if m&(1<<(8-uint(i))) != 0 {
			b[i+1] = byte(c)
		}
	}
	return string(b)
}

func (s *Shell) longLine(dir string, e dirEntry) string {
	p := path.Join(dir, e.name)
	links := 1
	if e.dir {
		links = 2
	}
	return fmt.Sprintf("%s %d %s %s %5d %s %s\n", modeString(e.dir, s.mode(p, e.dir)), links, s.user, s.user, e.size,
		s.Now().UTC().Format("Jan _2 15:04"), e.name)
}

func (s *Shell) ls(args []string) outcome {
	long, all := false, false
	var targets []string
	for _, a := range args {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			long = long || strings.Contains(a, "l")
			all = all || strings.ContainsAny(a, "aA")
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		targets = []string{s.cwd}
	}
	var out, errs strings.Builder
	code := 0
	for _, t := range targets {
		p := s.resolve(t)
		switch body, isFile := s.file(p); {
		case s.isDir(p):
			if len(targets) > 1 {
				fmt.Fprintf(&out, "%s:\n", t)
			}
			var names []string
			var lines strings.Builder
			if all {
				names = []string{".", ".."}
				if long {
					lines.WriteString(s.longLine(p, dirEntry{name: ".", dir: true, size: 4096}))
					lines.WriteString(s.longLine(p, dirEntry{name: "..", dir: true, size: 4096}))
				}
			}
			for _, e := range s.list(p) {
				if !all && strings.HasPrefix(e.name, ".") {
					continue
				}
				names = append(names, e.name)
				if long {
					lines.WriteString(s.longLine(p, e))
				}
			}
			switch {
			case len(names) == 0:
			case long:
				fmt.Fprintf(&out, "total %d\n%s", 4*len(names), lines.String())
			default:
				out.WriteString(strings.Join(names, "  ") + "\n")
			}
		case isFile:
			if long {
				out.WriteString(s.longLine(path.Dir(p), dirEntry{name: t, size: len(body)}))
			} else {
				out.WriteString(t + "\n")
			}
		default:
			fmt.Fprintf(&errs, "ls: cannot access '%s': No such file or directory\n", t)
			code = 2
		}
	}
	return outcome{out: out.String(), err: errs.String(), code: code}
}

func (s *Shell) cat(args []string) outcome {
	var out, errs strings.Builder
	code := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := s.resolve(a)
		if body, ok := s.file(p); ok {
			out.WriteString(body)
			continue
		}
		code = 1
		if s.isDir(p) {
			fmt.Fprintf(&errs, "cat: %s: Is a directory\n", a)
			continue
		}
		fmt.Fprintf(&errs, "cat: %s: No such file or directory\n", a)
	}
	return outcome{out: out.String(), err: errs.String(), code: code}
}

func (s *Shell) mkdirCmd(args []string) outcome {
	parents := false
	var errs strings.Builder
	code := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			parents = parents || strings.Contains(a, "p")
			continue
		}
		if reason := s.mkdir(s.resolve(a), parents); reason != "" {
			fmt.Fprintf(&errs, "mkdir: cannot create directory '%s': %s\n", a, reason)
			code = 1
		}
	}
	return outcome{err: errs.String(), code: code}
}

func (s *Shell) touch(args []string) outcome {
	var errs strings.Builder
	code := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := s.resolve(a)
		if s.isDir(p) {
			continue
		}
		if _, ok := s.file(p); ok {
			continue
		}
		if reason := s.writeFile(p, "", false); reason != "" {
			fmt.Fprintf(&errs, "touch: cannot touch '%s': %s\n", a, reason)
			code = 1
		}
	}
	return outcome{err: errs.String(), code: code}
}

func (s *Shell) rm(args []string) outcome {
	recursive, force := false, false
	var errs strings.Builder
	code := 0
	for _, a := range args {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			recursive = recursive || strings.ContainsAny(a, "rR")
			force = force || strings.Contains(a, "f")
			continue
		}
		p := s.resolve(a)
		switch {
		case s.isDir(p):
			if !recursive {
				fmt.Fprintf(&errs, "rm: cannot remove '%s': Is a directory\n", a)
				code = 1
				continue
			}
			s.removeTree(p)
		default:
			if _, ok := s.file(p); !ok {
				if !force {
					fmt.Fprintf(&errs, "rm: cannot remove '%s': No such file or directory\n", a)
					code = 1
				}
				continue
			}
			s.removeFile(p)
		}
	}
	return outcome{err: errs.String(), code: code}
}

func (s *Shell) removeFile(p string) {
	s.fs.bytes -= len(s.fs.files[p])
	delete(s.fs.files, p)
	delete(s.fs.modes, p)
	if _, ok := s.baseFiles[p]; ok {
		s.fs.gone[p] = true
	}
}

// removeTree deletes what the client created under p; the canned directories
// stay.
func (s *Shell) removeTree(p string) {
	prefix := strings.TrimSuffix(p, "/") + "/"
	for f := range s.fs.files {
		if strings.HasPrefix(f, prefix) {
			s.removeFile(f)
		}
	}
	for d := range s.fs.dirs {
		if d == p || strings.HasPrefix(d, prefix) {
			delete(s.fs.dirs, d)
			delete(s.fs.modes, d)
		}
	}
}

func (s *Shell) chmod(args []string) outcome {
	var mode string
	var paths []string
	for _, a := range args {
		switch {
		case mode == "" && len(a) > 0 && !(strings.HasPrefix(a, "-") && len(a) > 1 && strings.Trim(a[1:], "Rfv") == ""):
			mode = a
		case strings.HasPrefix(a, "-") && len(a) > 1 && strings.Trim(a[1:], "Rfv") == "":
		default:
			paths = append(paths, a)
		}
	}
	if mode == "" {
		return fail(1, "chmod: missing operand")
	}
	var errs strings.Builder
	code := 0
	for _, a := range paths {
		p := s.resolve(a)
		dir := s.isDir(p)
		if _, ok := s.file(p); !ok && !dir {
			fmt.Fprintf(&errs, "chmod: cannot access '%s': No such file or directory\n", a)
			code = 1
			continue
		}
		if m, ok := applyMode(mode, s.mode(p, dir)); ok {
			s.fs.modes[p] = m
		}
	}
	return outcome{err: errs.String(), code: code}
}

// applyMode applies an octal or a symbolic ([ugoa]*[+-=][rwx]+) mode to old.
func applyMode(mode string, old uint32) (uint32, bool) {
	if n, err := strconv.ParseUint(mode, 8, 32); err == nil {
		return uint32(n) & 0o7777, true
	}
	i := strings.IndexAny(mode, "+-=")
	if i < 0 || i+1 >= len(mode) {
		return old, false
	}
	who := uint32(0o777)
	if w := mode[:i]; w != "" {
		who = 0
		for _, c := range w {
			switch c {
			case 'u':
				who |= 0o700
			case 'g':
				who |= 0o070
			case 'o':
				who |= 0o007
			case 'a':
				who |= 0o777
			default:
				return old, false
			}
		}
	}
	var perm uint32
	for _, c := range mode[i+1:] {
		switch c {
		case 'r':
			perm |= 0o444
		case 'w':
			perm |= 0o222
		case 'x':
			perm |= 0o111
		default:
			return old, false
		}
	}
	perm &= who
	switch mode[i] {
	case '+':
		return old | perm, true
	case '-':
		return old &^ perm, true
	}
	return old&^who | perm, true
}

func (s *Shell) files() map[string]string {
	p := s.persona
	var cpu strings.Builder
	for i := 0; i < p.Cores; i++ {
		fmt.Fprintf(&cpu, "processor\t: %d\nvendor_id\t: GenuineIntel\nmodel name\t: %s\ncpu MHz\t\t: 2400.000\ncache size\t: 30720 KB\n\n", i, p.CPU)
	}
	return map[string]string{
		"/etc/hostname": p.Hostname + "\n",
		"/etc/hosts":    "127.0.0.1 localhost\n127.0.1.1 " + p.Hostname + "\n",
		"/etc/issue":    p.Pretty + " \\n \\l\n\n",
		"/etc/os-release": fmt.Sprintf("PRETTY_NAME=\"%s\"\nNAME=\"%s\"\nVERSION_ID=\"%s\"\nID=%s\n",
			p.Pretty, strings.SplitN(p.Pretty, " ", 2)[0], p.Release, p.ID),
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
			"sys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n",
		"/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
		"/proc/cpuinfo":    cpu.String(),
		"/proc/version":    fmt.Sprintf("Linux version %s (buildd@lcy02) (gcc (GCC) 11.4.0) %s\n", p.Kernel, p.Build),
		"/proc/uptime":     "3543120.55 14012345.12\n",
	}
}

// echo prints its arguments; -n drops the newline and -e reads backslash
// escapes (\n, \t, \xHH, \0NNN), as bots use to write binary.
func echo(args []string) string {
	newline, escapes := true, false
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "neE") == "" {
		newline = newline && !strings.Contains(args[0], "n")
		escapes = escapes || strings.Contains(args[0], "e")
		args = args[1:]
	}
	text := strings.Join(args, " ")
	if escapes {
		text = unescape(text)
	}
	if newline {
		text += "\n"
	}
	return text
}

func unescape(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out = append(out, s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case 'a':
			out = append(out, 7)
		case '\\':
			out = append(out, '\\')
		case 'x':
			j := i + 1
			for j < len(s) && j < i+3 && strings.IndexByte("0123456789abcdefABCDEF", s[j]) >= 0 {
				j++
			}
			if n, err := strconv.ParseUint(s[i+1:j], 16, 8); err == nil {
				out = append(out, byte(n))
				i = j - 1
				continue
			}
			out = append(out, '\\', 'x')
		case '0':
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint(s[i+1:j], 8, 8)
			out = append(out, byte(n))
			i = j - 1
		default:
			out = append(out, '\\', s[i])
		}
	}
	return string(out)
}
