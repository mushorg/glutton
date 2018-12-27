package glutton

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

// Mirai botnet  - https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
// Hajime botnet - https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf
var miraiCom = map[string][]string{
	"ps":                                 []string{"1 pts/21   00:00:00 init"},
	"cat /proc/mounts":                   []string{"rootfs / rootfs rw 0 0\r\n/dev/root / ext2 rw,relatime,errors=continue 0 0\r\nproc /proc proc rw,relatime 0 0\r\nsysfs /sys sysfs rw,relatime 0 0\r\nudev /dev tmpfs rw,relatime 0 0\r\ndevpts /dev/pts devpts rw,relatime,mode=600,ptmxmode=000 0 0\r\n/dev/mtdblock1 /home/hik jffs2 rw,relatime 0 0\r\ntmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0\r\n"},
	"(cat .s || cp /bin/echo .s)":        []string{"cat: .s: No such file or directory"},
	"nc":                                 []string{"nc: command not found"},
	"wget":                               []string{"wget: missing URL"},
	"(dd bs=52 count=1 if=.s || cat .s)": []string{"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\xbc\x14\x01\x00\x34\x00\x00\x00"},
	"sh":                                 []string{"$"},
	"sh || shell":                        []string{"$"},
	"enable\x00":                         []string{"-bash: enable: command not found"},
	"system\x00":                         []string{"-bash: system: command not found"},
	"shell\x00":                          []string{"-bash: shell: command not found"},
	"sh\x00":                             []string{"$"},
	//	"fgrep XDVR /mnt/mtd/dep2.sh\x00":		   []string{"cd /mnt/mtd && ./XDVRStart.hisi ./td3500 &"},
	"busybox": []string{"BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"},
	"echo -ne '\\x48\\x6f\\x6c\\x6c\\x61\\x46\\x6f\\x72\\x41\\x6c\\x6c\\x61\\x68\\x0a'\r\n": []string{"\x48\x6f\x6c\x6c\x61\x46\x6f\x72\x41\x6c\x6c\x61\x68\x0arn"},
	"cat | sh": []string{""},
	"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": []string{""},
	"cat /dev/.nippon": []string{"kami/dev"},
	"rm /dev/.nippon":  []string{""},
	"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": []string{""},
	"cat /run/.nippon":              []string{"kami/run"},
	"rm /run/.nippon":               []string{""},
	"cat /bin/sh":                   []string{"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x28\x00\x01\x00\x00\x00\x98\x30\x00\x00\x34\x00\x00\x00"},
	"/bin/busybox ps":               []string{"1 pts/21   00:00:00 init"},
	"/bin/busybox cat /proc/mounts": []string{"tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0"},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": []string{""},
	"/bin/busybox cat /dev/.nippon":                                []string{"kami/dev"},
	"/bin/busybox rm /dev/.nippon":                                 []string{""},
	"/bin/busybox echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": []string{""},
	"/bin/busybox cat /run/.nippon":                                []string{"kami/run"},
	"/bin/busybox rm /run/.nippon":                                 []string{""},
	"/bin/busybox cat /bin/sh":                                     []string{""},
	"/bin/busybox cat /bin/echo":                                   []string{"/bin/busybox cat /bin/echo\r\n\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x6c\xb9\x00\x00\x34\x00\x00\x00"},
	"rm /dev/.human":                                               []string{"rm: can't remove '/.t': No such file or directory\r\nrm: can't remove '/.sh': No such file or directory\r\nrm: can't remove '/.human': No such file or directory\r\ncd /dev"},
}

func writeMsg(conn net.Conn, msg string, g *Glutton) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := g.processor.Connections.GetByFlow(ck)

	g.logger.Info(
		"telnet send",
		zap.String("handler", "telnet"),
		zap.String("msg", fmt.Sprintf("%q", msg)),
		zap.String("direction", "send"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
	)
	if g.producer != nil && md != nil {
		if err := g.producer.Log(conn, md, []byte(msg)); err != nil {
			return err
		}
	}
	return nil
}

func readMsg(conn net.Conn, g *Glutton) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := g.processor.Connections.GetByFlow(ck)

	g.logger.Info(
		"telnet recv",
		zap.String("handler", "telnet"),
		zap.String("msg", fmt.Sprintf("%q", msg)),
		zap.String("direction", "recv"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
	)
	if g.producer != nil && md != nil {
		if err = g.producer.Log(conn, md, []byte(msg)); err != nil {
			return
		}
	}
	return
}

func getSample(cmd string, g *Glutton) error {
	url := cmd[strings.Index(cmd, "http"):]
	url = strings.Split(url, " ")[0]
	timeout := time.Duration(5 * time.Second)
	client := http.Client{Timeout: timeout}
	g.logger.Info(fmt.Sprintf("[telnet  ] getSample target URL: %s", url))
	resp, err := client.Get(url)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample http error: %v", err))
		return err
	}
	if resp.StatusCode != 200 {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample read http: error: Non 200 status code on getSample"))
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength <= 0 {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample read http: error: Empty response body"))
		return err
	}
	bodyBuffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample read http: %v", err))
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
		g.logger.Info(fmt.Sprintf("[telnet  ] getSample already known"))
		return nil
	}
	out, err := os.Create(path)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample create error: %v", err))
		return err
	}
	defer out.Close()
	_, err = out.Write(bodyBuffer)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] getSample write error: %v", err))
		return err
	}
	g.logger.Info(
		"new sample fetched from telnet",
		zap.String("handler", "telnet"),
		zap.String("sha256", sha256Hash),
		zap.String("source", url),
	)
	return nil
}

// HandleTelnet handles telnet communication on a connection
func (g *Glutton) HandleTelnet(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		if err = conn.Close(); err != nil {
			g.logger.Error(fmt.Sprintf("[telnet  ]  error: %v", err))
		}
	}()

	// TODO (glaslos): Add device banner

	// telnet window size negotiation response
	if err = writeMsg(conn, "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27", g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return err
	}

	// User name prompt
	if err = writeMsg(conn, "Username: ", g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return err
	}
	if _, err = readMsg(conn, g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return
	}
	if err = writeMsg(conn, "Password: ", g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return err
	}
	if _, err = readMsg(conn, g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return
	}

	if err = writeMsg(conn, "welcome\r\n> ", g); err != nil {
		g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
		return err
	}

	for {
		g.updateConnectionTimeout(ctx, conn)
		msg, err := readMsg(conn, g)
		if err != nil {
			g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
			return err
		}
		for _, cmd := range strings.Split(msg, ";") {
			if strings.Contains(strings.Trim(cmd, " "), "wget http") {
				go getSample(strings.Trim(cmd, " "), g)
			}
			if strings.TrimRight(cmd, "") == " rm /dev/.t" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == " rm /dev/.sh" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == "cd /dev/" {
				if err = writeMsg(conn, "ECCHI: applet not found\r\n", g); err != nil {
					g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
					return err
				}
				if err = writeMsg(conn, "\r\nBusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n", g); err != nil {
					g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
					return err
				}
				continue
			}

			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				if err = writeMsg(conn, resp[rand.Intn(len(resp))]+"\r\n", g); err != nil {
					g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
					return err
				}
			} else {
				// /bin/busybox YDKBI
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					if err = writeMsg(conn, match[1]+": applet not found\r\n", g); err != nil {
						g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
						return err
					}
					if err = writeMsg(conn, "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n", g); err != nil {
						g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
						return err
					}
				}
			}
		}
		if err := writeMsg(conn, "> ", g); err != nil {
			g.logger.Error(fmt.Sprintf("[telnet  ] error: %v", err))
			return err
		}
	}
}
