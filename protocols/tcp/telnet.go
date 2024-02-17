package tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

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
	events []parsedTelnet
	client *http.Client
}

// write writes a telnet message to the connection
func (s *telnetServer) write(conn net.Conn, msg string) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	s.events = append(s.events, parsedTelnet{Direction: "write", Message: msg})
	return nil
}

// read reads a telnet message from a connection
func (s *telnetServer) read(conn net.Conn) (string, error) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return msg, err
	}
	s.events = append(s.events, parsedTelnet{Direction: "read", Message: msg})
	return msg, err
}

func (s *telnetServer) getSample(cmd string, logger interfaces.Logger) error {
	url := cmd[strings.Index(cmd, "http"):]
	url = strings.Split(url, " ")[0]
	logger.Info(fmt.Sprintf("getSample target URL: %s", url))
	resp, err := s.client.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("getSample read http: error: Non 200 status code on getSample")
	}
	defer resp.Body.Close()
	if resp.ContentLength <= 0 {
		return errors.New("getSample read http: error: Empty response body")
	}
	bodyBuffer, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bodyBuffer)
	// Ignoring errors for if the folder already exists
	if err = os.MkdirAll("samples", os.ModePerm); err != nil {
		return err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join("samples", sha256Hash)
	if _, err = os.Stat(path); err == nil {
		logger.Info("getSample already known", slog.String("sha", sha256Hash))
		return nil
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.Write(bodyBuffer)
	if err != nil {
		return err
	}
	logger.Info(
		"new sample fetched from telnet",
		slog.String("handler", "telnet"),
		slog.String("sha256", sha256Hash),
		slog.String("source", url),
	)
	return nil
}

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	s := &telnetServer{
		events: []parsedTelnet{},
		client: &http.Client{
			Timeout: time.Duration(5 * time.Second),
		},
	}
	defer func() {
		if err := h.ProduceTCP("telnet", conn, md, []byte(helpers.FirstOrEmpty[parsedTelnet](s.events).Message), s.events); err != nil {
			logger.Error("failed to produce message", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close telnet connection", producer.ErrAttr(err))
		}
	}()

	// TODO (glaslos): Add device banner

	// telnet window size negotiation response
	if err := s.write(conn, "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"); err != nil {
		return err
	}

	// User name prompt
	if err := s.write(conn, "Username: "); err != nil {
		return err
	}
	if _, err := s.read(conn); err != nil {
		return err
	}
	if err := s.write(conn, "Password: "); err != nil {
		return err
	}
	if _, err := s.read(conn); err != nil {
		return err
	}
	if err := s.write(conn, "welcome\r\n> "); err != nil {
		return err
	}

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		msg, err := s.read(conn)
		if err != nil {
			return err
		}
		for _, cmd := range strings.Split(msg, ";") {
			if strings.Contains(strings.Trim(cmd, " "), "wget http") {
				go s.getSample(strings.Trim(cmd, " "), logger)
			}
			if strings.TrimRight(cmd, "") == " rm /dev/.t" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == " rm /dev/.sh" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == "cd /dev/" {
				if err := s.write(conn, "ECCHI: applet not found\r\n"); err != nil {
					return err
				}

				if err := s.write(conn, "\r\nBusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"); err != nil {
					return err
				}
				continue
			}

			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				if err := s.write(conn, resp[rand.Intn(len(resp))]+"\r\n"); err != nil {
					return err
				}
			} else {
				// /bin/busybox YDKBI
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					if err := s.write(conn, match[1]+": applet not found\r\n"); err != nil {
						return err
					}

					if err := s.write(conn, "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"); err != nil {
						return err
					}
				}
			}
		}
		if err := s.write(conn, "> "); err != nil {
			return err
		}
	}
}
