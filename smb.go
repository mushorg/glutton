package glutton

import (
	"encoding/hex"
	"net"

	"github.com/mushorg/glutton/protocols/smb"
)

// HandleSMB takes a net.Conn and does basic SMB communication
func (g *Glutton) HandleSMB(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			g.Logger.Errorf("[smb     ] error: %v", err)
		}
		if err != nil && n <= 0 {
			break
		}
		if n > 0 {
			g.Logger.Infof("[smb     ]\n%s", hex.Dump(buffer[0:n]))
			packet, err := smb.ParseSMB(buffer[0:n])
			if err != nil {
				g.Logger.Errorf("[smb     ] error: %v", err)
			}
			g.Logger.Infof("[smb     ] req packet: %+v", packet)
			if len(packet.Data.DialectString) > 0 {
				g.Logger.Infof("[smb     ] data: %s", string(packet.Data.DialectString[:]))
			}
		}
	}
}
