package glutton

import (
	"encoding/hex"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
)

func HandleTCP(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Error(err)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(10))
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	if n > 0 {
		log.Infof("[log.tcp ] %s\n%s", host, hex.Dump(buffer[0:n]))
	} else {
		log.Infof("[log.tcp ] %s", host)
	}
}
