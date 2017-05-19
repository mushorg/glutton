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
		if err != nil && n <= 0 {
			g.logger.Errorf("[smb     ] error: %v", err)
			break
		}
		if n > 0 && n < 1024 {
			g.logger.Infof("[smb     ]\n%s", hex.Dump(buffer[0:n]))
			packet, err := smb.ParseSMB(buffer[0:n])
			if err != nil {
				g.logger.Errorf("[smb     ] error: %v", err)
			}
			g.logger.Infof("[smb     ] req packet: %+v", packet)
			if len(packet.Data.DialectString) > 0 {
				g.logger.Infof("[smb     ] data: %s", string(packet.Data.DialectString[:]))
				resp, err := smb.MakeNegotiateProtocolResponse(&packet)
				if err != nil {
					g.logger.Errorf("[smb     ] error: %v", err)
				}
				g.logger.Infof("[smb     ] resp packet: %+v", resp)
				conn.Write(resp)
			}
		}
	}
}
