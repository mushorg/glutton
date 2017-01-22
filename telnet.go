package glutton

import (
	"bufio"
	"math/rand"
	"net"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
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
}

func writeMsg(conn net.Conn, msg string) error {
	_, err := conn.Write([]byte(msg))
	log.Infof("[TELNET -> %v] Payload: %q", conn.RemoteAddr(), msg)
	return err
}

func readMsg(conn net.Conn) (string, error) {
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	log.Infof("[%v -> TELNET] Payload: %q", conn.RemoteAddr(), message)
	return message, err
}

// HandleTelnet handles telnet communication on a connection
func HandleTelnet(conn net.Conn) {
	defer conn.Close()

	// TODO (glaslos): Add device banner
	// User name prompt
	writeMsg(conn, "Username: ")
	_, err := readMsg(conn)
	if err != nil {
		log.Error(err)
		return
	}
	writeMsg(conn, "Password: ")
	_, err = readMsg(conn)
	if err != nil {
		log.Error(err)
		return
	}

	writeMsg(conn, "welcome\r\n> ")
	for {
		msg, err := readMsg(conn)
		if err != nil {
			log.Error(err)
			return
		}
		for _, cmd := range strings.Split(msg, ";") {
			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				writeMsg(conn, resp[rand.Intn(len(resp))]+"\r\n")
			} else {
				// /bin/busybox YDKBI
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					writeMsg(conn, match[1]+": applet not found\r\n")
				}
			}
		}
		writeMsg(conn, "> ")
	}
}
