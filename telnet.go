package glutton

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

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
	return err
}

func readMsg(conn net.Conn) (string, error) {
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return message, err
}

func handleTelnet(conn net.Conn) error {
	defer conn.Close()
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
	fmt.Printf("[*] Successful login with username: %s and password: %s\n", username, password)
	writeMsg(conn, "welcome\n> ")
	for {
		msg, err := readMsg(conn)
		if err != nil {
			return err
		}
		fmt.Printf("[*] Telnet message: %s", msg)
		if resp := miraiCom[strings.TrimSpace(msg)]; resp != "" {
			writeMsg(conn, resp+"\n")
		}
		writeMsg(conn, "> ")
	}
}
