package ssh

import (
	"fmt"
	"strings"
	"time"
)

// Statuses of a Result.
const (
	StatusOK       = "ok"
	StatusNotFound = "not-found" // the command is not emulated
)

// Shell is a fake bash session. It never touches the host: every answer is
// canned, and downloaders (wget, curl, tftp) fail as if the network were
// down, so the honeypot does not fetch attacker-supplied URLs.
type Shell struct {
	persona Persona
	user    string
	cwd     string
	// Now is the clock for date and uptime; tests replace it.
	Now func() time.Time
}

// NewShell starts a session for user on persona.
func NewShell(p Persona, user string) *Shell {
	s := &Shell{persona: p, user: user, Now: time.Now}
	s.cwd = s.home()
	return s
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
	Output string // stdout and stderr, "\n" line ends
	Status string // StatusOK, or StatusNotFound when the last command is unknown
	Exit   bool   // the session ends (exit, logout)
}

// Run executes one input line. Commands joined with ;, && or || all run, and
// a pipeline runs only its first command.
func (s *Shell) Run(line string) Result {
	res := Result{Status: StatusOK}
	var out strings.Builder
	for _, cmd := range splitCommands(line) {
		fields := strings.Fields(cmd)
		if len(fields) == 0 {
			continue
		}
		o, status, exit := s.command(fields, strings.Contains(cmd, ">"))
		out.WriteString(o)
		res.Status = status
		if exit {
			res.Exit = true
			break
		}
	}
	res.Output = out.String()
	return res
}

// splitCommands splits on ;, && and || outside quotes and drops everything
// after the first | of each command.
func splitCommands(line string) []string {
	var cmds []string
	var cur strings.Builder
	var quote rune
	piped := false
	flush := func() {
		cmds = append(cmds, cur.String())
		cur.Reset()
		piped = false
	}
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ';' || c == '\n':
			flush()
			continue
		case c == '&' && i+1 < len(runes) && runes[i+1] == '&', c == '|' && i+1 < len(runes) && runes[i+1] == '|':
			i++
			flush()
			continue
		case c == '|':
			piped = true
		}
		if !piped {
			cur.WriteRune(c)
		}
	}
	flush()
	return cmds
}

// command runs one simple command. redirected suppresses stdout, as in
// `echo x > file`.
func (s *Shell) command(f []string, redirected bool) (string, string, bool) {
	name, args := f[0], f[1:]
	if name == "sudo" && len(args) > 0 {
		name, args = args[0], args[1:]
	}
	out, ok, exit := s.builtin(name, args)
	if !ok {
		return fmt.Sprintf("bash: %s: command not found\n", name), StatusNotFound, false
	}
	if redirected {
		out = ""
	}
	return out, StatusOK, exit
}

func (s *Shell) builtin(name string, args []string) (out string, ok, exit bool) {
	p := s.persona
	switch name {
	case "exit", "logout":
		return "logout\n", true, true
	case "whoami":
		return s.user + "\n", true, false
	case "id":
		if s.user == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\n", true, false
		}
		return fmt.Sprintf("uid=1000(%[1]s) gid=1000(%[1]s) groups=1000(%[1]s),27(sudo)\n", s.user), true, false
	case "pwd":
		return s.cwd + "\n", true, false
	case "hostname":
		return p.Hostname + "\n", true, false
	case "uname":
		return s.uname(args), true, false
	case "nproc":
		return fmt.Sprintf("%d\n", p.Cores), true, false
	case "date":
		return s.Now().UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n", true, false
	case "uptime":
		now := s.Now().UTC()
		return fmt.Sprintf(" %s up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n", now.Format("15:04:05")), true, false
	case "cd":
		return s.cd(args), true, false
	case "ls", "dir":
		return s.ls(args), true, false
	case "cat":
		return s.cat(args), true, false
	case "echo":
		return echo(args), true, false
	case "ps":
		return "    PID TTY          TIME CMD\n   1042 pts/0    00:00:00 bash\n   1067 pts/0    00:00:00 ps\n", true, false
	case "history":
		return "", true, false
	case "crontab":
		return "no crontab for " + s.user + "\n", true, false
	case "free":
		return "               total        used        free      shared  buff/cache   available\nMem:         4025044      612340     2410288        1264      1002416     3207612\nSwap:              0           0           0\n", true, false
	case "wget":
		return "wget: unable to resolve host address\n", true, false
	case "curl":
		return "curl: (6) Could not resolve host\n", true, false
	case "tftp", "ftpget":
		return name + ": can't resolve host\n", true, false
	case "busybox":
		if len(args) > 0 {
			return args[0] + ": applet not found\n", true, false
		}
		return "", true, false
	case "export", "unset", "set", "unalias", "alias", "chmod", "chown", "rm", "mkdir", "touch", "kill", "pkill",
		"killall", "sleep", "nohup", "source", ".", "ulimit", "umask", "clear", "setsid", "sync", "mv", "cp",
		"systemctl", "service", "iptables", "passwd", "chattr", "true":
		return "", true, false
	}
	return "", false, false
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

// dirs maps the directories the shell can enter to their listing.
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

func (s *Shell) resolve(path string) string {
	switch {
	case path == "" || path == "~":
		return s.home()
	case strings.HasPrefix(path, "~/"):
		path = s.home() + path[1:]
	case !strings.HasPrefix(path, "/"):
		path = strings.TrimSuffix(s.cwd, "/") + "/" + path
	}
	var stack []string
	for _, seg := range strings.Split(path, "/") {
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

func (s *Shell) cd(args []string) string {
	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	dir := s.resolve(target)
	if _, ok := s.dirs()[dir]; !ok {
		return fmt.Sprintf("bash: cd: %s: No such file or directory\n", target)
	}
	s.cwd = dir
	return ""
}

func (s *Shell) ls(args []string) string {
	dir := s.cwd
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			dir = s.resolve(a)
		}
	}
	listing, ok := s.dirs()[dir]
	if !ok {
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", strings.Join(args, " "))
	}
	if listing == "" {
		return ""
	}
	return listing + "\n"
}

func (s *Shell) cat(args []string) string {
	var out strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		path := s.resolve(a)
		if body, ok := s.files()[path]; ok {
			out.WriteString(body)
			continue
		}
		if _, ok := s.dirs()[path]; ok {
			fmt.Fprintf(&out, "cat: %s: Is a directory\n", a)
			continue
		}
		fmt.Fprintf(&out, "cat: %s: No such file or directory\n", a)
	}
	return out.String()
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

// echo prints its arguments, dropping the quotes and an -n/-e flag.
func echo(args []string) string {
	for len(args) > 0 && (args[0] == "-n" || args[0] == "-e" || args[0] == "-ne") {
		args = args[1:]
	}
	text := strings.Join(args, " ")
	text = strings.NewReplacer("\"", "", "'", "").Replace(text)
	if i := strings.IndexByte(text, '>'); i >= 0 {
		text = text[:i]
	}
	return text + "\n"
}
