package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
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
)

// busyboxBanner is the BusyBox ash greeting Mirai checks for after applet probes.
const busyboxBanner = "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"

// maxTelnetSample caps bytes fetched from wget/curl URLs.
const maxTelnetSample = 10 << 20

// Mirai botnet  - https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
// Hajime botnet - https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf
var miraiCom = map[string][]string{
	"ps":                                 {"1 pts/21   00:00:00 init"},
	"cat /proc/mounts":                   {"rootfs / rootfs rw 0 0\r\n/dev/root / ext2 rw,relatime,errors=continue 0 0\r\nproc /proc proc rw,relatime 0 0\r\nsysfs /sys sysfs rw,relatime 0 0\r\nudev /dev tmpfs rw,relatime 0 0\r\ndevpts /dev/pts devpts rw,relatime,mode=600,ptmxmode=000 0 0\r\n/dev/mtdblock1 /home/hik jffs2 rw,relatime 0 0\r\ntmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0\r\n"},
	"(cat .s || cp /bin/echo .s)":        {"cat: .s: No such file or directory"},
	"nc":                                 {"nc: command not found"},
	"wget":                               {"wget: missing URL"},
	"(dd bs=52 count=1 if=.s || cat .s)": {"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\xbc\x14\x01\x00\x34\x00\x00\x00"},
	"sh":                                 {"$"},
	"sh || shell":                        {"$"},
	"enable\x00":                         {"-bash: enable: command not found"},
	"linuxshell\x00":                     {"-bash: linuxshell: command not found"},
	"system\x00":                         {"-bash: system: command not found"},
	"shell\x00":                          {"-bash: shell: command not found"},
	"sh\x00":                             {"$"},
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
	"cat /bin/sh":                   {"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x28\x00\x01\x00\x00\x00\x98\x30\x00\x00\x34\x00\x00\x00"},
	"/bin/busybox ps":               {"1 pts/21   00:00:00 init"},
	"/bin/busybox cat /proc/mounts": {"tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0"},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": {""},
	"/bin/busybox cat /dev/.nippon":                                {"kami/dev"},
	"/bin/busybox rm /dev/.nippon":                                 {""},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": {""},
	"/bin/busybox cat /run/.nippon":                                {"kami/run"},
	"/bin/busybox rm /run/.nippon":                                 {""},
	"/bin/busybox cat /bin/sh":                                     {""},
	"/bin/busybox cat /bin/echo":                                   {"/bin/busybox cat /bin/echo\r\n\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x6c\xb9\x00\x00\x34\x00\x00\x00"},
	"rm /dev/.human":                                               {"rm: can't remove '/.t': No such file or directory\r\nrm: can't remove '/.sh': No such file or directory\r\nrm: can't remove '/.human': No such file or directory\r\ncd /dev"},
}

type parsedTelnet struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Path        string `json:"path,omitempty"` // wget/curl URL when present
	Message     string `json:"message,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type telnetServer struct {
	events   []parsedTelnet
	conn     net.Conn
	reader   *bufio.Reader
	client   *http.Client
	step     string
	sampleWG sync.WaitGroup
	sampleMu sync.Mutex
	samples  map[int]string // event index -> sample hash
}

func newTelnetServer(conn net.Conn) *telnetServer {
	return &telnetServer{
		events:  []parsedTelnet{},
		conn:    conn,
		reader:  bufio.NewReader(conn),
		client:  &http.Client{Timeout: 5 * time.Second},
		samples: map[int]string{},
	}
}

func telnetShellCommand(msg string) string {
	line := strings.TrimRight(msg, "\r\n\x00")
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if idx := strings.IndexAny(line, " \t"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func telnetCredential(msg string) string {
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
	line := strings.TrimRight(cmd, "\r\n\x00")
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
	s.events = append(s.events, parsedTelnet{Direction: "write", Command: telnetWriteCommand(msg), Message: msg})
	return nil
}

// stripTelnetIAC removes telnet negotiation sequences from data.
// Negotiation octets are returned separately so they can be recorded as their own frames.
func stripTelnetIAC(data []byte) (cleaned, negotiation []byte) {
	cleaned = make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] != 0xff {
			cleaned = append(cleaned, data[i])
			i++
			continue
		}
		if i+1 >= len(data) {
			negotiation = append(negotiation, data[i])
			break
		}
		cmd := data[i+1]
		switch cmd {
		case 0xff: // escaped 0xff data byte
			cleaned = append(cleaned, 0xff)
			i += 2
		case 251, 252, 253, 254: // WILL / WONT / DO / DONT + option
			end := i + 3
			if end > len(data) {
				end = len(data)
			}
			negotiation = append(negotiation, data[i:end]...)
			i = end
		case 250: // SB ... IAC SE
			start := i
			i += 2
			for i < len(data) {
				if data[i] == 0xff && i+1 < len(data) && data[i+1] == 240 {
					i += 2
					break
				}
				i++
			}
			negotiation = append(negotiation, data[start:i]...)
		default: // two-byte IAC command
			end := i + 2
			if end > len(data) {
				end = len(data)
			}
			negotiation = append(negotiation, data[i:end]...)
			i = end
		}
	}
	return cleaned, negotiation
}

// read reads a telnet message from a connection
func (s *telnetServer) read() (string, error) {
	msg, err := s.reader.ReadString('\n')
	if len(msg) > 0 {
		cleaned, negotiation := stripTelnetIAC([]byte(msg))
		if len(negotiation) > 0 {
			s.events = append(s.events, parsedTelnet{Direction: "read", Message: string(negotiation)})
		}
		if len(cleaned) > 0 {
			cmd := ""
			switch s.step {
			case "username", "password":
				cmd = s.step
			default:
				cmd = telnetShellCommand(string(cleaned))
			}
			s.events = append(s.events, parsedTelnet{Direction: "read", Command: cmd, Message: string(cleaned)})
		}
		return string(cleaned), err
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
	s.sampleWG.Add(1)
	go func() {
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
	defer func() {
		s.applySampleHashes()
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

	if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	// TODO (glaslos): Add device banner

	// telnet window size negotiation response
	if err := s.write("\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"); err != nil {
		endReason = connection.EndWriteError
		return err
	}

	// User name prompt
	if err := s.write("Username: "); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	s.step = "username"
	userMsg, err := s.read()
	if err != nil {
		logger.Debug("Failed to read from connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	username := telnetCredential(userMsg)
	if err := s.write("Password: "); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	s.step = "password"
	passMsg, err := s.read()
	if err != nil {
		logger.Debug("Failed to read from connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	password := telnetCredential(passMsg)
	logger.Info(
		"telnet login",
		slog.String("handler", "telnet"),
		slog.String("src_ip", host),
		slog.String("src_port", srcPort),
		slog.String("dest_port", destPort),
		slog.String("username", username),
		slog.String("password", password),
	)
	if err := s.write("welcome\r\n> "); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	s.step = "shell"

	for {
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "telnet"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		msg, err := s.read()
		if err != nil {
			logger.Debug("Failed to read from connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		logger.Debug(
			"telnet command",
			slog.String("handler", "telnet"),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
			slog.String("dest_port", destPort),
			slog.String("command", telnetShellCommand(msg)),
			slog.String("message", telnetCredential(msg)),
		)
		if url, ok := telnetDownloadURL(msg); ok {
			if idx := s.lastReadEventIndex(); idx >= 0 {
				s.events[idx].Path = url
				s.startSampleFetch(idx, url, logger)
			}
		}
		skipPrompt := false
		for _, cmd := range strings.Split(msg, ";") {
			if strings.TrimRight(cmd, "") == " rm /dev/.t" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == " rm /dev/.sh" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == "cd /dev/" {
				if err := s.write("ECCHI: applet not found\r\n"); err != nil {
					return err
				}

				if err := s.write(busyboxBanner); err != nil {
					return err
				}
				continue
			}

			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(len(resp))))
				if err != nil {
					return err
				}
				reply := resp[n.Int64()]
				if err := s.write(reply + "\r\n"); err != nil {
					return err
				}
				// sh already emits a prompt; do not append "> " after it.
				if reply == "$" {
					skipPrompt = true
				}
			} else {
				// /bin/busybox YDKBI
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Za-z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					if err := s.write(match[1] + ": applet not found\r\n"); err != nil {
						return err
					}

					if err := s.write(busyboxBanner); err != nil {
						return err
					}
				}
			}
		}
		if skipPrompt {
			continue
		}
		if err := s.write("> "); err != nil {
			return err
		}
	}
}
