package glutton

import (
	"bufio"
	"math/rand"
	"net"
	"regexp"
	"strings"

	"github.com/kung-foo/freki"
)

// Based on https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
var miraiCom = map[string][]string{
	"ps":                                              []string{"1 pts/21   00:00:00 init"},
	"cat /proc/mounts":                                []string{"tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3231524k,mode=755 0 0"},
	"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": []string{""},
	"cat /dev/.nippon":                                []string{"kami/dev"},
	"rm /dev/.nippon":                                 []string{""},
	"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": []string{""},
	"cat /run/.nippon":                                []string{"kami/run"},
	"rm /run/.nippon":                                 []string{""},
	"cat /bin/sh":                                     []string{""},
}

func writeMsg(conn net.Conn, msg string, g *Glutton) error {
	_, err := conn.Write([]byte(msg))
	g.logger.Infof("[telnet  ] send: %q", msg)
	md := g.processor.Connections.GetByFlow(freki.NewConnKeyFromNetConn(conn))
	g.producer.LogHTTP(conn, md, msg, "write")
	return err
}

func readMsg(conn net.Conn, g *Glutton) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	g.logger.Infof("[telnet  ] recv: %q", msg)
	md := g.processor.Connections.GetByFlow(freki.NewConnKeyFromNetConn(conn))
	g.producer.LogHTTP(conn, md, msg, "read")
	return msg, err
}

// HandleTelnet handles telnet communication on a connection
func (g *Glutton) HandleTelnet(conn net.Conn) {
	defer conn.Close()

	// TODO (glaslos): Add device banner
	// User name prompt
	writeMsg(conn, "Username: ", g)
	_, err := readMsg(conn, g)
	if err != nil {
		g.logger.Errorf("[telnet  ] %v", err)
		return
	}
	writeMsg(conn, "Password: ", g)
	_, err = readMsg(conn, g)
	if err != nil {
		g.logger.Errorf("[telnet  ] %v", err)
		return
	}

	writeMsg(conn, "welcome\r\n> ", g)
	for {
		msg, err := readMsg(conn, g)
		if err != nil {
			g.logger.Errorf("[telnet  ] %v", err)
			return
		}
		for _, cmd := range strings.Split(msg, ";") {
			if strings.TrimRight(cmd, "") == " rm /dev/.t" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == " rm /dev/.sh" {
				continue
			}
			if strings.TrimRight(cmd, "\r\n") == "cd /dev/" {
				writeMsg(conn, "ECCHI: applet not found\r\n", g)
				writeMsg(conn, "\r\nBusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-it shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n", g)
				continue
			}

			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				writeMsg(conn, resp[rand.Intn(len(resp))]+"\r\n", g)
			} else {
				// /bin/busybox YDKBI
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					writeMsg(conn, match[1]+": applet not found\r\n", g)
					writeMsg(conn, "BusyBox v1.16.1 (2014-03-04 16:00:18 CST) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n", g)
				}
			}
		}
		writeMsg(conn, "> ", g)
	}
}
