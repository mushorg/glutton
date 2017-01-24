package glutton

import (
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/mushorg/glutton/rdp"
)

func HandleRDP(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Errorf("[rdp     ] error: %v", err)
	}
	if n > 0 {
		pdu, err := rdp.ParsePDU(buffer)
		if err != nil {
			log.Errorf("[rdp     ] error: %v", err)
		}
		log.Infof("[rdp     ] pdu: %+v", pdu)
		if len(pdu.Data) > 0 {
			log.Infof("[rdp     ] data: %s", string(pdu.Data))
		}
	}
}
