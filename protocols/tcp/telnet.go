package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
)

// busyboxBanner is the BusyBox ash greeting Mirai checks for after applet probes.
const busyboxBanner = "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"

// busyboxUsage is what a bare `busybox` / `/bin/busybox` prints: the multi-call
// header followed by the applet list.
const busyboxUsage = "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) multi-call binary\r\n" +
	"Copyright (C) 1998-2009 Erik Andersen, Rob Landley, Denys Vlasenko\r\n" +
	"and others. Licensed under GPLv2.\r\n" +
	"See source distribution for full notice.\r\n\r\n" +
	"Usage: busybox [function] [arguments]...\r\n" +
	"   or: function [arguments]...\r\n\r\n" +
	"\tBusyBox is a multi-call binary that combines many common Unix\r\n" +
	"\tutilities into a single executable.\r\n\r\n" +
	"Currently defined functions:\r\n" +
	"\t[, ash, busybox, cat, cd, chmod, cp, dd, echo, ftpget, grep, head, kill,\r\n" +
	"\tkillall, ln, ls, mkdir, mount, mv, ping, ps, rm, sh, sleep, tail, tftp,\r\n" +
	"\ttouch, uname, wget\r\n\r\n"

// busyboxPingUsage is what `ping` prints without a host.
const busyboxPingUsage = "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) multi-call binary\r\n\r\n" +
	"Usage: ping [OPTIONS] HOST\r\n\r\n"

// maxTelnetSample caps bytes fetched from wget/curl URLs.
const maxTelnetSample = 10 << 20

const (
	// maxTelnetLine caps one recorded line; long echo -ne droppers fit.
	maxTelnetLine = 64 << 10
	// maxTelnetFrames caps the frames kept per connection; the session ends
	// with max_frames once it is reached.
	maxTelnetFrames = 1000
	// maxTelnetSampleFetches caps downloads per connection.
	maxTelnetSampleFetches = 8
)

// telnetFetchSlots bounds sample downloads in flight across all connections
// (each may buffer maxTelnetSample); a download beyond it is skipped.
var telnetFetchSlots = make(chan struct{}, 32)

// telnetOptionRequests opens the session: IAC DO TERMINAL-TYPE, TERMINAL-SPEED,
// X-DISPLAY-LOCATION and NEW-ENVIRON.
const telnetOptionRequests = "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"

// telnetPrompt is written after each shell line.
const telnetPrompt = "> "

// telnetShPrompt is written after commands once `sh` has switched the
// session into the BusyBox shell. Same bytes as the pre-sh prompt: this fleet
// answers `> ` for enable/linuxshell/system/shell and stalls on anything else
// after `sh` (`$ `, `~ # `, `\r\n> `; Ochi event 1997a98e-cfb2-48dc-88bf-d487b3a0a3c9).
const telnetShPrompt = telnetPrompt

// telnetShReply is unused as a distinct write: `sh` is silent like enable
// (the loop writes telnetShPrompt). Kept so skipPrompt can still mark inSh
// if a canned sh reply is added back.
const telnetShReply = telnetShPrompt

// telnetGreeting is the prompt written after a successful login.
const telnetGreeting = "welcome\r\n> "

// Mirai botnet  - https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
// Hajime botnet - https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf
var miraiCom = map[string][]string{
	"ps":                          {"1 pts/21   00:00:00 init"},
	"cat /proc/mounts":            {"rootfs / rootfs rw 0 0\r\n/dev/root / ext2 rw,relatime,errors=continue 0 0\r\nproc /proc proc rw,relatime 0 0\r\nsysfs /sys sysfs rw,relatime 0 0\r\nudev /dev tmpfs rw,relatime 0 0\r\ndevpts /dev/pts devpts rw,relatime,mode=600,ptmxmode=000 0 0\r\n/dev/mtdblock1 /home/hik jffs2 rw,relatime 0 0\r\ntmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0\r\n"},
	"(cat .s || cp /bin/echo .s)": {"cat: .s: No such file or directory"},
	"nc":                          {"nc: command not found"},
	"wget":                        {"wget: missing URL"},
	// enable / linuxshell / system / shell / sh are silent: a body with ':'
	// (old "-bash: X: command not found") is a false Mirai prompt, and a
	// distinct sh write (`$ `, `~ # `, `\r\n> `) stalled this fleet after it
	// had answered every bare "> ". The loop still writes "> ".
	//	"fgrep XDVR /mnt/mtd/dep2.sh\x00":		   {"cd /mnt/mtd && ./XDVRStart.hisi ./td3500 &"},
	"busybox": {busyboxBanner},
	"echo -ne '\\x48\\x6f\\x6c\\x6c\\x61\\x46\\x6f\\x72\\x41\\x6c\\x6c\\x61\\x68\\x0a'\r\n": {"\x48\x6f\x6c\x6c\x61\x46\x6f\x72\x41\x6c\x6c\x61\x68\x0arn"},
	"cat | sh": {""},
	"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": {""},
	"cat /dev/.nippon": {"kami/dev"},
	"rm /dev/.nippon":  {""},
	"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": {""},
	"cat /run/.nippon":              {"kami/run"},
	"rm /run/.nippon":               {""},
	"/bin/busybox ps":               {"1 pts/21   00:00:00 init"},
	"/bin/busybox cat /proc/mounts": {"tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0"},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": {""},
	"/bin/busybox cat /dev/.nippon":                                {"kami/dev"},
	"/bin/busybox rm /dev/.nippon":                                 {""},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": {""},
	"/bin/busybox cat /run/.nippon":                                {"kami/run"},
	"/bin/busybox rm /run/.nippon":                                 {""},
	"/bin/busybox cat /bin/sh":                                     {""},
	"rm /dev/.human":                                               {"rm: can't remove '/.t': No such file or directory\r\nrm: can't remove '/.sh': No such file or directory\r\nrm: can't remove '/.human': No such file or directory\r\ncd /dev"},
}

// telnetELFReplies are commands that print the fake BusyBox binary (/bin/sh,
// /bin/echo, its copy .s, /proc/self/exe): Mirai reads the ELF header and
// picks a loader by e_machine. Values are text printed before the header.
var telnetELFReplies = map[string]string{
	"(dd bs=52 count=1 if=.s || cat .s)": "",
	"cat /bin/sh":                        "",
	"cat /proc/self/exe":                 "",
	"cat /bin/busybox":                   "",
	"/bin/busybox cat /bin/echo":         "/bin/busybox cat /bin/echo\r\n",
}

// telnetArch is the CPU the fake device claims in its ELF headers.
type telnetArch struct {
	name    string
	data    byte // EI_DATA: 1 little-endian, 2 big-endian
	machine uint16
	entry   uint32
	flags   uint32
	// greeting is written after login; errStyle picks how unknown commands are
	// reported ("bash", "sh" or "ash"). arm keeps the original persona.
	greeting string
	errStyle string
}

// telnetArches is the rotation order for returning sources; arm (the
// original persona) comes first.
var telnetArches = []telnetArch{
	{name: "arm", data: 1, machine: 0x28, entry: 0xb96c, flags: 0x05000200, greeting: telnetGreeting, errStyle: "bash"},       // EABI5 soft-float
	{name: "mips", data: 2, machine: 0x08, entry: 0x400190, flags: 0x00001007, greeting: "Welcome\r\n> ", errStyle: "sh"},     // o32, noreorder, pic, cpic
	{name: "mipsel", data: 1, machine: 0x08, entry: 0x400190, flags: 0x00001007, greeting: "Welcome!\r\n> ", errStyle: "ash"}, // o32, noreorder, pic, cpic
}

// elfHeader returns the 52-byte ELF32 header of the fake BusyBox static executable.
func (a telnetArch) elfHeader() string {
	var order binary.ByteOrder = binary.LittleEndian
	if a.data == 2 {
		order = binary.BigEndian
	}
	h := make([]byte, 52)
	copy(h, "\x7fELF\x01")
	h[5] = a.data
	h[6] = 1                   // EI_VERSION
	order.PutUint16(h[16:], 2) // e_type EXEC
	order.PutUint16(h[18:], a.machine)
	order.PutUint32(h[20:], 1) // e_version
	order.PutUint32(h[24:], a.entry)
	order.PutUint32(h[28:], 52)      // e_phoff
	order.PutUint32(h[32:], 0xc1f2c) // e_shoff
	order.PutUint32(h[36:], a.flags)
	order.PutUint16(h[40:], 52) // e_ehsize
	order.PutUint16(h[42:], 32) // e_phentsize
	order.PutUint16(h[44:], 5)  // e_phnum
	order.PutUint16(h[46:], 40) // e_shentsize
	order.PutUint16(h[48:], 27) // e_shnum
	order.PutUint16(h[50:], 26) // e_shstrndx
	return string(h)
}

// telnetReplies is miraiCom keyed by normalized command, so NUL- and
// CRLF-terminated variants of the same command share one entry.
var telnetReplies = func() map[string][]string {
	m := make(map[string][]string, len(miraiCom))
	for k, v := range miraiCom {
		m[normalizeTelnetCommand(k)] = v
	}
	return m
}()

// busyboxApplets are applets the fake BusyBox has; any other `/bin/busybox X`
// is answered with "X: applet not found" (Mirai's BusyBox liveness check).
var busyboxApplets = map[string]bool{
	"ash": true, "busybox": true, "cat": true, "cd": true, "chmod": true, "cp": true,
	"dd": true, "echo": true, "ftpget": true, "grep": true, "head": true, "kill": true,
	"killall": true, "ln": true, "ls": true, "mkdir": true, "mount": true, "mv": true,
	"ping": true, "ps": true, "rm": true, "sh": true, "sleep": true, "tail": true,
	"tftp": true, "touch": true, "uname": true, "wget": true,
}

var busyboxAppletRe = regexp.MustCompile(`/bin/busybox\s+([A-Za-z0-9_]+)(.*)`)

// normalizeTelnetCommand trims whitespace and NUL terminators from a shell command.
func normalizeTelnetCommand(cmd string) string {
	return strings.TrimFunc(cmd, func(r rune) bool {
		return r == 0 || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

// telnetLookup finds a canned reply for a normalized command, falling back to
// the same command without a `/bin/busybox ` prefix. elf is true when the
// reply is an ELF header of arch.
func telnetLookup(cmd string, arch telnetArch) (resp []string, elf, ok bool) {
	if resp, elf, ok := telnetLookupExact(cmd, arch); ok {
		return resp, elf, true
	}
	if rest, found := strings.CutPrefix(cmd, "/bin/busybox "); found {
		return telnetLookupExact(normalizeTelnetCommand(rest), arch)
	}
	return nil, false, false
}

// telnetLookupExact finds a canned or ELF reply for exactly cmd.
func telnetLookupExact(cmd string, arch telnetArch) (resp []string, elf, ok bool) {
	if resp, ok := telnetReplies[cmd]; ok {
		return resp, false, true
	}
	if prefix, ok := telnetELFReplies[cmd]; ok {
		return []string{prefix + arch.elfHeader()}, true, true
	}
	return nil, false, false
}

// telnetAppletReply emulates BusyBox for commands without a canned reply:
// unknown applets are "not found", cat of an unknown file is a missing file.
func telnetAppletReply(cmd string) []string {
	var applet, args string
	if cmd == "/bin/busybox" {
		return []string{busyboxUsage}
	}
	if m := busyboxAppletRe.FindStringSubmatch(cmd); m != nil {
		applet, args = m[1], m[2]
		if !busyboxApplets[applet] {
			return []string{applet + ": applet not found\r\n", busyboxBanner}
		}
	} else {
		applet, args, _ = strings.Cut(cmd, " ")
	}
	if applet == "ping" && strings.TrimSpace(args) == "" {
		return []string{busyboxPingUsage}
	}
	if applet != "cat" {
		return nil
	}
	if idx := strings.IndexAny(args, "|<>&"); idx >= 0 {
		args = args[:idx]
	}
	var out strings.Builder
	for _, f := range strings.Fields(args) {
		if strings.HasPrefix(f, "-") {
			continue
		}
		out.WriteString("cat: ")
		out.WriteString(f)
		out.WriteString(": No such file or directory\r\n")
	}
	if out.Len() == 0 {
		return nil
	}
	return []string{out.String()}
}

// telnetResponse is what the shell writes for one command.
type telnetResponse struct {
	out        []string
	skipPrompt bool // sh printed its own prompt
	variant    bool // out depends on the visit's architecture
}

// telnetReply returns the frames to write for one `;`-separated shell command.
// For `a || b` the first alternative with a canned reply wins.
func telnetReply(cmd string, arch telnetArch) (telnetResponse, error) {
	line := normalizeTelnetCommand(cmd)
	if line == "" {
		return telnetResponse{}, nil
	}
	// Try the whole line first, then each `||` alternative in order.
	candidates := []string{line}
	alts := []string{line}
	if strings.Contains(line, "||") {
		alts = alts[:0]
		for _, alt := range strings.Split(line, "||") {
			if alt = normalizeTelnetCommand(alt); alt != "" {
				alts = append(alts, alt)
			}
		}
		candidates = append(candidates, alts...)
	}
	for _, c := range candidates {
		resp, elf, ok := telnetLookup(c, arch)
		if !ok || len(resp) == 0 {
			continue
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(resp))))
		if err != nil {
			return telnetResponse{}, err
		}
		reply := resp[n.Int64()]
		// sh emits a real shell prompt (no CRLF); do not append "> ".
		if reply == telnetShReply {
			return telnetResponse{out: []string{telnetShReply}, skipPrompt: true}, nil
		}
		return telnetResponse{out: []string{reply + "\r\n"}, variant: elf}, nil
	}
	if len(alts) == 0 {
		return telnetResponse{}, nil
	}
	return telnetResponse{out: telnetAppletReply(alts[0])}, nil
}

type parsedTelnet struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Path        string `json:"path,omitempty"` // wget/curl URL when present
	Message     string `json:"message,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Variant     string `json:"variant,omitempty"`   // architecture variant, on writes that depend on it
	Visit       int    `json:"visit,omitempty"`     // source's visit number, on writes that depend on it
	OffsetMs    int64  `json:"offset_ms,omitempty"` // milliseconds since the connection was accepted
	Truncated   bool   `json:"truncated,omitempty"` // line cut at maxTelnetLine, or last read kept at maxTelnetFrames
}

type telnetServer struct {
	events   []parsedTelnet
	conn     net.Conn
	reader   *bufio.Reader
	client   *http.Client
	step     string
	inSh     bool // `sh` has run: the prompt is telnetShPrompt and errors are ash-style
	started  time.Time
	sampleWG sync.WaitGroup
	sampleMu sync.Mutex
	samples  map[int]string // event index -> sample hash
	fetches  int            // downloads started on this connection

	// Recall: the architecture is picked once per connection.
	srcIP net.IP
	visit int // 0 until begin
	arch  telnetArch
	store *recall.Store
}

func newTelnetServer(conn net.Conn) *telnetServer {
	return &telnetServer{
		events:  []parsedTelnet{},
		conn:    conn,
		reader:  bufio.NewReader(conn),
		client:  &http.Client{Timeout: 5 * time.Second},
		samples: map[int]string{},
		started: telnetNow(),
		srcIP:   remoteIP(conn),
		arch:    telnetArches[0],
	}
}

// telnetNow is the clock behind parsedTelnet.OffsetMs; tests swap it.
var telnetNow = time.Now

// add records one frame with its offset from the start of the connection.
func (s *telnetServer) add(ev parsedTelnet) {
	ev.OffsetMs = telnetNow().Sub(s.started).Milliseconds()
	s.events = append(s.events, ev)
}

// tagLast stamps the last write frame with the visit's variant.
func (s *telnetServer) tagLast() {
	ev := &s.events[len(s.events)-1]
	ev.Variant = s.arch.name
	ev.Visit = s.visit
}

// telnetRecall remembers each source's last visit; tests swap it for a store
// with a fake clock.
var telnetRecall = recall.Shared

// begin picks the architecture once per connection: a source returning after
// recall.visit_gap gets the next telnetArches entry.
func (s *telnetServer) begin(logger interfaces.Logger) {
	if s.visit > 0 {
		return
	}
	s.store = telnetRecall
	v := s.store.Begin("telnet", s.srcIP, len(telnetArches))
	s.visit, s.arch = v.Number, telnetArches[v.Variant]
	if v.Started && v.Number > 1 {
		logger.Info("returning telnet source",
			slog.String("protocol", "telnet"),
			slog.String("src_ip", s.srcIP.String()),
			slog.Int("visit", v.Number),
			slog.String("variant", s.arch.name),
			slog.String("previous_variant", v.Previous.Variant),
			slog.Any("previous_commands", v.Previous.Commands),
		)
	}
}

// note stores what the source did on this connection.
func (s *telnetServer) note() {
	if s.visit == 0 {
		return
	}
	s.store.Note("telnet", s.srcIP, func(sum *recall.Summary) {
		sum.Variant = s.arch.name
		sum.Events++
		for _, e := range s.events {
			if e.Direction != "read" {
				continue
			}
			switch e.Command {
			case "username":
				sum.AddUsername(trimTelnetLine(e.Message))
			case "password":
			default:
				sum.AddCommand(e.Command)
				sum.AddPath(e.Path)
			}
		}
	})
}

// styleNotFound rewrites the bash-style "not found" reply to the architecture's
// shell flavour. It reports whether the reply changed.
func (a telnetArch) styleNotFound(reply string) (string, bool) {
	var out string
	switch a.errStyle {
	case "sh":
		rest, ok := strings.CutPrefix(reply, "-bash: ")
		if !ok {
			return reply, false
		}
		out = "-sh: " + rest
	case "ash":
		out = ashNotFound(reply)
	default:
		return reply, false
	}
	return out, out != reply
}

// restyleNotFound adapts a bash-style "not found" reply to the session's
// shell: BusyBox ash once inside `sh`, otherwise the architecture's persona.
// restyled reports a persona-dependent change.
func (s *telnetServer) restyleNotFound(reply string) (out string, restyled bool) {
	if s.inSh {
		return ashNotFound(reply), false
	}
	return s.arch.styleNotFound(reply)
}

// ashNotFound rewrites a bash-style "-bash: X: command not found" reply as the
// BusyBox ash "sh: X: not found" once the session is inside `sh`.
func ashNotFound(reply string) string {
	rest, ok := strings.CutPrefix(reply, "-bash: ")
	if !ok {
		return reply
	}
	name, ok := strings.CutSuffix(rest, ": command not found\r\n")
	if !ok {
		return reply
	}
	return "sh: " + name + ": not found\r\n"
}

// telnetShellCommand returns the first word of a shell line, recorded as the
// read frame's command.
func telnetShellCommand(msg string) string {
	line := strings.TrimSpace(trimTelnetLine(msg))
	if line == "" {
		return ""
	}
	// Cut at whitespace or a shell operator so `ping; sh` records `ping`.
	if idx := strings.IndexAny(line, " \t;|&"); idx > 0 {
		return line[:idx]
	}
	return line
}

// trimTelnetLine drops the line terminator (CR, LF, NUL) from a read line.
func trimTelnetLine(msg string) string {
	return strings.TrimRight(msg, "\r\n\x00")
}

func telnetWriteCommand(msg string) string {
	switch msg {
	case "Username: ":
		return "username"
	case "Password: ":
		return "password"
	default:
		return ""
	}
}

// telnetDownloadURL extracts an http(s) URL from a wget/curl shell line.
func telnetDownloadURL(cmd string) (string, bool) {
	line := trimTelnetLine(cmd)
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "wget") && !strings.Contains(lower, "curl") {
		return "", false
	}
	idx := strings.Index(lower, "http://")
	if idx < 0 {
		idx = strings.Index(lower, "https://")
	}
	if idx < 0 {
		return "", false
	}
	url := line[idx:]
	if end := strings.IndexAny(url, " \t\r\n;|&\"'"); end >= 0 {
		url = url[:end]
	}
	if url == "" {
		return "", false
	}
	return url, true
}

// write writes a telnet message to the connection
func (s *telnetServer) write(msg string) error {
	if _, err := s.conn.Write([]byte(msg)); err != nil {
		return err
	}
	s.add(parsedTelnet{Direction: "write", Command: telnetWriteCommand(msg), Message: msg})
	return nil
}

// Telnet command octets (RFC 854).
const (
	telnetIAC  = 0xff // interpret as command
	telnetSE   = 240  // end of subnegotiation
	telnetSB   = 250  // start of subnegotiation
	telnetWILL = 251
	telnetWONT = 252
	telnetDO   = 253
	telnetDONT = 254
)

// stripTelnetIAC removes telnet negotiation sequences from data.
// Negotiation octets are returned separately so they can be recorded as their own frames.
func stripTelnetIAC(data []byte) (cleaned, negotiation []byte) {
	cleaned = make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] != telnetIAC {
			cleaned = append(cleaned, data[i])
			i++
			continue
		}
		if i+1 >= len(data) {
			negotiation = append(negotiation, data[i])
			break
		}
		switch data[i+1] {
		case telnetIAC: // escaped 0xff data byte
			cleaned = append(cleaned, telnetIAC)
			i += 2
		case telnetWILL, telnetWONT, telnetDO, telnetDONT: // + option byte
			end := min(i+3, len(data))
			negotiation = append(negotiation, data[i:end]...)
			i = end
		case telnetSB: // SB ... IAC SE
			start := i
			i += 2
			for i < len(data) {
				if data[i] == telnetIAC && i+1 < len(data) && data[i+1] == telnetSE {
					i += 2
					break
				}
				i++
			}
			negotiation = append(negotiation, data[start:i]...)
		default: // two-byte IAC command
			end := min(i+2, len(data))
			negotiation = append(negotiation, data[i:end]...)
			i = end
		}
	}
	return cleaned, negotiation
}

// telnetTextStart reports whether b can open a telnet session: IAC or text.
func telnetTextStart(b byte) bool {
	return b == telnetIAC || b == '\r' || b == '\n' || b == '\t' || b == 0 || (b >= 0x20 && b < 0x7f)
}

// readBinary records whatever the client sent as a single unlabeled frame.
func (s *telnetServer) readBinary() error {
	buf := make([]byte, maxBufferSize)
	n, err := s.reader.Read(buf)
	if n > 0 {
		data := append([]byte(nil), buf[:n]...)
		cmd := "binary"
		if n >= 2 && data[0] == 0x16 && data[1] == 0x03 {
			cmd = "tls_client_hello"
		}
		s.add(parsedTelnet{Direction: "read", Command: cmd, Message: string(data)})
	}
	return err
}

// read reads one line, recording any IAC negotiation and the remaining text as
// separate read frames, and returns the text.
func (s *telnetServer) read() (string, error) {
	line, truncated, err := helpers.ReadLine(s.reader, maxTelnetLine)
	cleaned, negotiation := stripTelnetIAC(line)
	if len(negotiation) > 0 {
		s.add(parsedTelnet{Direction: "read", Message: string(negotiation)})
	}
	msg := string(cleaned)
	if msg != "" {
		var cmd string
		switch s.step {
		case "username", "password":
			cmd = s.step
		default:
			cmd = telnetShellCommand(msg)
		}
		s.add(parsedTelnet{Direction: "read", Command: cmd, Message: msg, Truncated: truncated})
	}
	return msg, err
}

func (s *telnetServer) fetchSample(url string, logger interfaces.Logger) (string, error) {
	logger.Debug("Fetching sample", slog.String("url", url), slog.String("handler", "telnet"))
	resp, err := s.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("failed to fetch sample: " + resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTelnetSample))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("empty response body")
	}

	sha256Hash, err := helpers.Store(data, "samples")
	if err != nil {
		return "", err
	}
	if sha256Hash == "" {
		sha256Hash = helpers.SHA256Hex(data)
	}

	logger.Info(
		"New sample fetched",
		slog.String("handler", "telnet"),
		slog.String("sample_hash", sha256Hash),
		slog.String("source", url),
	)
	return sha256Hash, nil
}

func (s *telnetServer) startSampleFetch(eventIdx int, url string, logger interfaces.Logger) {
	if s.fetches >= maxTelnetSampleFetches {
		logger.Debug("Skipping sample fetch, per-connection limit reached", slog.String("handler", "telnet"), slog.String("source", url))
		return
	}
	select {
	case telnetFetchSlots <- struct{}{}:
	default:
		logger.Debug("Skipping sample fetch, too many in flight", slog.String("handler", "telnet"), slog.String("source", url))
		return
	}
	s.fetches++
	s.sampleWG.Add(1)
	go func() {
		defer func() { <-telnetFetchSlots }()
		defer s.sampleWG.Done()
		hash, err := s.fetchSample(url, logger)
		if err != nil {
			logger.Error("Failed to get sample", slog.String("handler", "telnet"), slog.String("source", url), producer.ErrAttr(err))
			return
		}
		s.sampleMu.Lock()
		s.samples[eventIdx] = hash
		s.sampleMu.Unlock()
	}()
}

func (s *telnetServer) applySampleHashes() {
	s.sampleWG.Wait()
	s.sampleMu.Lock()
	defer s.sampleMu.Unlock()
	for idx, hash := range s.samples {
		if idx >= 0 && idx < len(s.events) {
			s.events[idx].PayloadHash = hash
		}
	}
}

// lastReadEventIndex returns the index of the most recent non-empty read frame.
func (s *telnetServer) lastReadEventIndex() int {
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Direction == "read" && s.events[i].Message != "" {
			return i
		}
	}
	return -1
}

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleTelnet(ctx, newTelnetServer(conn), md, logger, h)
}

func handleTelnet(ctx context.Context, s *telnetServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	endReason := connection.EndHandlerClose
	s.begin(logger)
	defer func() {
		s.applySampleHashes()
		s.note()
		md.EndReason = endReason
		if err := h.ProduceTCP("telnet", s.conn, md, []byte(helpers.FirstOrEmpty(s.events).Message), s.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		}
		if err := s.conn.Close(); err != nil {
			logger.Debug("Failed to close telnet connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		}
	}()

	host, srcPort, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	destPort := strconv.Itoa(int(md.TargetPort))
	connAttrs := func(extra ...any) []any {
		return append([]any{
			slog.String("handler", "telnet"),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
			slog.String("dest_port", destPort),
		}, extra...)
	}

	// Each way the session can end records its reason for the produced event.
	// Timeouts and read errors are expected attacker behavior, not failures.
	timedOut := func(err error) error {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	readFailed := func(err error) error {
		logger.Debug("Failed to read from connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	writeFailed := func(err error) error {
		endReason = connection.EndWriteError
		return err
	}

	if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
		return timedOut(err)
	}

	// TODO (glaslos): Add device banner

	if err := s.write(telnetOptionRequests); err != nil {
		return writeFailed(err)
	}

	if err := s.write("Username: "); err != nil {
		return writeFailed(err)
	}
	s.step = "username"
	first, err := s.reader.Peek(1)
	if err != nil {
		return readFailed(err)
	}
	if !telnetTextStart(first[0]) {
		// Not telnet (e.g. a TLS ClientHello): do not treat it as credentials.
		err := s.readBinary()
		logger.Debug("Non-telnet data on telnet port", slog.String("protocol", "telnet"), slog.String("src_ip", host), slog.String("dest_port", destPort), producer.ErrAttr(err))
		return nil
	}
	userMsg, err := s.read()
	if err != nil {
		return readFailed(err)
	}

	if err := s.write("Password: "); err != nil {
		return writeFailed(err)
	}
	s.step = "password"
	passMsg, err := s.read()
	if err != nil {
		return readFailed(err)
	}

	logger.Info("telnet login", connAttrs(
		slog.String("username", trimTelnetLine(userMsg)),
		slog.String("password", trimTelnetLine(passMsg)),
	)...)
	if err := s.write(s.arch.greeting); err != nil {
		return writeFailed(err)
	}
	if s.arch.greeting != telnetGreeting {
		s.tagLast()
	}
	s.step = "shell"

	for {
		if len(s.events) >= maxTelnetFrames {
			if idx := s.lastReadEventIndex(); idx >= 0 {
				s.events[idx].Truncated = true
			}
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			return timedOut(err)
		}
		msg, err := s.read()
		if err != nil {
			return readFailed(err)
		}
		logger.Debug("telnet command", connAttrs(
			slog.String("command", telnetShellCommand(msg)),
			slog.String("message", trimTelnetLine(msg)),
		)...)
		if err := s.runShellLine(msg, logger); err != nil {
			return writeFailed(err)
		}
	}
}

// runShellLine answers one shell line: the replies for each `;`-separated
// command, then the prompt. A wget/curl URL on the line starts a sample fetch.
func (s *telnetServer) runShellLine(msg string, logger interfaces.Logger) error {
	if url, ok := telnetDownloadURL(msg); ok {
		if idx := s.lastReadEventIndex(); idx >= 0 {
			s.events[idx].Path = url
			s.startSampleFetch(idx, url, logger)
		}
	}
	skipPrompt := false
	for _, cmd := range strings.Split(msg, ";") {
		if strings.TrimRight(cmd, "\r\n") == "cd /dev/" {
			if err := s.write("ECCHI: applet not found\r\n"); err != nil {
				return err
			}
			if err := s.write(busyboxBanner); err != nil {
				return err
			}
			continue
		}

		resp, err := telnetReply(cmd, s.arch)
		if err != nil {
			return err
		}
		skipPrompt = skipPrompt || resp.skipPrompt
		for _, reply := range resp.out {
			reply, restyled := s.restyleNotFound(reply)
			if err := s.write(reply); err != nil {
				return err
			}
			if resp.variant || restyled {
				s.tagLast()
			}
		}
	}
	if skipPrompt {
		// sh printed its own prompt and switched the session into the BusyBox shell.
		s.inSh = true
		return nil
	}
	if s.inSh {
		return s.write(telnetShPrompt)
	}
	return s.write(telnetPrompt)
}
