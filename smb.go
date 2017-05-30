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
			buffer, err := smb.ValidateData(buffer[0:n])
			if err != nil {
				g.logger.Errorf("[smb     ] error: %v", err)
				return
			}
			header := smb.SMBHeader{}
			err = smb.ParseHeader(buffer, &header)
			if err != nil {
				g.logger.Errorf("[smb     ] error: %v", err)
			}
			g.logger.Infof("[smb     ] req packet: %+v", header)
			switch header.Command {
			case 0x72, 0x73, 0x75:
				resp, err := smb.MakeNegotiateProtocolResponse(header)
				if err != nil {
					g.logger.Errorf("[smb     ] error: %v", err)
				}
				conn.Write(resp)
			case 0x32:
				resp, err := smb.MakeComTransaction2Response(header)
				if err != nil {
					g.logger.Errorf("[smb     ] error: %v", err)
				}
				conn.Write(resp)
			case 0x25:
				resp, err := smb.MakeComTransactionResponse(header)
				if err != nil {
					g.logger.Errorf("[smb     ] error: %v", err)
					continue
				}
				conn.Write(resp)
			}
		}
	}
}
