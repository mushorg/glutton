package glutton

import (
	"bufio"
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
)

func readFTP(conn net.Conn) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Errorf("[ftp     ] error: %v", err)
	}
	log.Printf("[ftp     ] recv: %q", msg)
	return
}

func HandleFTP(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("220 Welcome!\r\n"))
	for {
		msg, err := readFTP(conn)
		if len(msg) < 1 && err != nil {
			break
		}
		cmd := strings.ToUpper(msg[:4])
		if cmd == "USER" {
			conn.Write([]byte("331 OK.\r\n"))
		} else if cmd == "PASS" {
			conn.Write([]byte("230 OK.\r\n"))
		} else {
			conn.Write([]byte("200 OK.\r\n"))
		}
	}
}
