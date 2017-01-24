package glutton

import (
	"bufio"
	"encoding/binary"
	"net"

	log "github.com/Sirupsen/logrus"
)

func readRFB(conn net.Conn) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Errorf("[rfb     ] error: %v", err)
	}
	log.Printf("[rfb     ] message %q", msg)
}

func HandleRFB(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("RFB 003.008\n"))
	readRFB(conn)
	var authNone uint32 = 1
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, authNone)
	conn.Write(bs)
	readRFB(conn)
}
