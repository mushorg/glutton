package glutton

import (
	"bufio"
	"log"
	"math/rand"
	"net"
	"regexp"
	"strings"
)

// ConnID is used to relate logs in a connection
var connID int64

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
	log.Printf("[%v] [TCP] [TELNET -> %v] Payload: %q", connID, conn.RemoteAddr(), msg)
	return err
}

func readMsg(conn net.Conn) (string, error) {
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	log.Printf("[%v] [TCP] [%v -> TELNET] Payload: %v", connID, conn.RemoteAddr(), message)
	return message, err
}

func handleTelnet(id int64, conn net.Conn) error {
	defer conn.Close()
	connID = id

	writeMsg(conn, "Username: ")
	_, err := readMsg(conn)
	if err != nil {
		return err
	}
	writeMsg(conn, "Password: ")
	_, err = readMsg(conn)
	if err != nil {
		return err
	}

	writeMsg(conn, "welcome\n> ")
	for {
		msg, err := readMsg(conn)
		if err != nil {
			return err
		}
		respMsg := ""
		for _, cmd := range strings.Split(msg, ";") {
			if resp := miraiCom[strings.TrimSpace(cmd)]; len(resp) > 0 {
				respMsg += resp[rand.Intn(len(resp))] + "\n"
			} else {
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					respMsg += match[1] + ": applet not found\n"
				}
			}
		}
		writeMsg(conn, respMsg)
		writeMsg(conn, "> ")
	}
}
