package glutton

import (
	"bufio"
	"net"
	"strings"
)

func readFTP(conn net.Conn, g *Glutton) (msg string, err error) {
	msg, err = bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		g.logger.Errorf("[ftp     ] error: %v", err)
	}
	g.logger.Infof("[ftp     ] recv: %q", msg)
	return
}

// HandleFTP takes a net.Conn and does basic FTP communication
func (g *Glutton) HandleFTP(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("220 Welcome!\r\n"))
	for {
		msg, err := readFTP(conn, g)
		if len(msg) < 4 || err != nil {
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
