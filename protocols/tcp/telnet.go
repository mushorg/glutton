package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

var MaliciousPatterns = []string{
	"wget http://",
	"tftp",
	"/bin/busybox",
	"bins.sh",
	".sh",
	"chmod 777",
	"ECCHI",
	"IHCCE",
}

var CommonCommands = map[string]string{
	"enable":  "system disabled",
	"system":  "error: system command disabled",
	"shell":   "shell access denied",
	"sh":      "sh: permission denied",
	"/bin/sh": "access denied",
}

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
	"system\x00":                         {"-bash: system: command not found"},
	"shell\x00":                          {"-bash: shell: command not found"},
	"sh\x00":                             {"$"},
	//	"fgrep XDVR /mnt/mtd/dep2.sh\x00":		   {"cd /mnt/mtd && ./XDVRStart.hisi ./td3500 &"},
	"busybox": {"BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"},
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
	Direction string `json:"direction,omitempty"`
	Message   string `json:"message,omitempty"`
}

type telnetServer struct {
	events            []parsedTelnet
	client            *http.Client
	commandHistory    []string
	maliciousAttempts int
	rateLimiter       *rate.Limiter
}

func ExtractURLs(cmd string) []string {
	urlPattern := regexp.MustCompile(`(http|tftp|ftp)://[^\s;>"']+`)
	return urlPattern.FindAllString(cmd, -1)
}

func ValidateURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func NewTelnetServer() *telnetServer {
	return &telnetServer{
		events: make([]parsedTelnet, 0),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		commandHistory:    make([]string, 0),
		maliciousAttempts: 0,
		rateLimiter:       rate.NewLimiter(rate.Every(1*time.Second), 5),
	}
}

// write writes a telnet message to the connection
func (s *telnetServer) write(conn net.Conn, msg string) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	s.events = append(s.events, parsedTelnet{Direction: "write", Message: msg})
	return nil
}

func (s *telnetServer) detectMaliciousCommand(cmd string) bool {
	for _, pattern := range MaliciousPatterns {
		if strings.Contains(cmd, pattern) {
			s.maliciousAttempts++
			return true
		}
	}
	return false
}

// read reads a telnet message from a connection
func (s *telnetServer) read(conn net.Conn) (string, error) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return msg, err
	}

	// Track command
	s.commandHistory = append(s.commandHistory, msg)
	s.detectMaliciousCommand(msg)

	s.events = append(s.events, parsedTelnet{Direction: "read", Message: msg})
	return msg, nil
}

func (s *telnetServer) getSample(cmd string, logger interfaces.Logger) error {
	if !s.rateLimiter.Allow() {
		logger.Debug("Rate limit exceeded for sample collection")
		return nil
	}

	urls := ExtractURLs(cmd)
	for _, url := range urls {
		if !ValidateURL(url) {
			continue
		}

		if err := s.downloadSample(url); err != nil {
			logger.Error("Failed to download sample",
				slog.String("url", url),
				producer.ErrAttr(err))
			continue
		}
	}
	return nil
}

func (s *telnetServer) downloadSample(url string) error {
	resp, err := s.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Generate unique filename
	filename := fmt.Sprintf("sample_%d_%s", time.Now().Unix(),
		filepath.Base(url))

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := NewTelnetServer()

	// Handle initial connection
	if err := server.write(conn, "Username: "); err != nil {
		return err
	}
	defer func() {
		if err := h.ProduceTCP("telnet", conn, md, []byte(helpers.FirstOrEmpty[parsedTelnet](server.events).Message), server.events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close telnet connection", producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		return nil
	}

	// TODO (glaslos): Add device banner

	// telnet window size negotiation response
	if err := server.write(conn, "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"); err != nil {
		return err
	}

	// User name prompt
	if err := server.write(conn, "Username: "); err != nil {
		return err
	}
	if _, err := server.read(conn); err != nil {
		logger.Debug("Failed to read from connection", slog.String("protocol", "telnet"), producer.ErrAttr(err))
		return nil
	}
	if err := server.write(conn, "Password: "); err != nil {
		return err
	}
	if _, err := server.read(conn); err != nil {
		return err
	}
	if err := server.write(conn, "welcome\r\n> "); err != nil {
		return err
	}
	for {
		cmd, err := server.read(conn)
		if err != nil {
			return err
		}

		// Check for malicious command
		if server.detectMaliciousCommand(cmd) {
			if err := server.getSample(cmd, logger); err != nil {
				logger.Error("Failed to get sample", producer.ErrAttr(err))
			}
		}

		// Handle common commands
		if response, exists := CommonCommands[strings.TrimSpace(cmd)]; exists {
			if err := server.write(conn, response+"\n"); err != nil {
				return err
			}
			continue
		}

		// Default response
		if err := server.write(conn, "command not found\n"); err != nil {
			return err
		}
	}
}
