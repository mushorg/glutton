package glutton

import (
	"encoding/hex"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/mushorg/glutton/rdp"
)

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Errorf("[rdp     ] error: %v", err)
	}
	if n > 0 {
		log.Infof("[rdp     ]\n%s", hex.Dump(buffer[0:n]))
		pdu, err := rdp.ParseCRPDU(buffer[0:n])
		if err != nil {
			log.Errorf("[rdp     ] error: %v", err)
		}
		log.Infof("[rdp     ] req pdu: %+v", pdu)
		if len(pdu.Data) > 0 {
			log.Infof("[rdp     ] data: %s", string(pdu.Data))
		}
		resp := rdp.ConnectionConfirm()
		log.Infof("[rdp     ] resp pdu: %+v", pdu)
		conn.Write(resp)
	}
}
