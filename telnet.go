package glutton

import (
	"bufio"
	"log"
	"net"
	"regexp"
	"strings"
)

// ConnID is used to relate logs in a connection
var connID int64

// Based on https://github.com/CymmetriaResearch/MTPot/blob/master/mirai_conf.json
var miraiCom = map[string]string{
	"ECCHI":                                           "ECCHI: applet not found",
	"ps":                                              "1 pts/21   00:00:00 init",
	"cat /proc/mounts":                                "tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=1635616k,mode=755 0 0",
	"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": "",
	"cat /dev/.nippon":                                "kami/dev",
	"rm /dev/.nippon":                                 "",
	"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": "",
	"cat /run/.nippon":                                "kami/run",
	"rm /run/.nippon":                                 "",
}

func writeMsg(conn net.Conn, msg string) error {
	_, err := conn.Write([]byte(msg))
	log.Printf("[%v] [TCP] [TELNET -> %v] Payload: %v", connID, conn.RemoteAddr(), msg)
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
	username, err := readMsg(conn)
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	writeMsg(conn, "Password: ")
	password, err := readMsg(conn)
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	log.Printf("Telnet login with username: '%s' and password: '%s'", username, password)

	writeMsg(conn, "welcome\n> ")
	for {
		msg, err := readMsg(conn)
		if err != nil {
			return err
		}
		for _, cmd := range strings.Split(msg, ";") {
			if resp := miraiCom[strings.TrimSpace(cmd)]; resp != "" {
				writeMsg(conn, resp+"\n")
			} else {
				re := regexp.MustCompile(`\/bin\/busybox (?P<applet>[A-Z]+)`)
				match := re.FindStringSubmatch(cmd)
				if len(match) > 1 {
					writeMsg(conn, match[1]+": applet not found\n")
				}
			}
		}
		writeMsg(conn, "> ")
	}
}
