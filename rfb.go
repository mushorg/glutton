package glutton

import (
	"bufio"
	"net"

	log "github.com/Sirupsen/logrus"
)

func HandleRFB(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("RFB 003.008\n"))
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Errorf("[rfb] error: %v", err)
	}
	log.Printf("[rfb ] message %q", msg)
}
