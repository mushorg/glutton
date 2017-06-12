package glutton

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/smb"
)

// HandleSMB takes a net.Conn and does basic SMB communication
func (g *Glutton) HandleSMB(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[smb     ]  error: %v", err))
		}
	}()

	buffer := make([]byte, 1024)
	for {
		g.updateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err != nil && n <= 0 {
			g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
			return err
		}
		if n > 0 && n < 1024 {
			g.logger.Info(fmt.Sprintf("[smb     ]\n%s", hex.Dump(buffer[0:n])))
			buffer, err := smb.ValidateData(buffer[0:n])
			if err != nil {
				g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
				return err
			}
			header := smb.SMBHeader{}
			err = smb.ParseHeader(buffer, &header)
			if err != nil {
				g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
			}
			g.logger.Info(fmt.Sprintf("[smb     ] req packet: %+v", header))
			switch header.Command {
			case 0x72, 0x73, 0x75:
				resp, err := smb.MakeNegotiateProtocolResponse(header)
				if err != nil {
					g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
				}
				conn.Write(resp)
			case 0x32:
				resp, err := smb.MakeComTransaction2Response(header)
				if err != nil {
					g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
				}
				conn.Write(resp)
			case 0x25:
				resp, err := smb.MakeComTransactionResponse(header)
				if err != nil {
					g.logger.Error(fmt.Sprintf("[smb     ] error: %v", err))
					continue
				}
				conn.Write(resp)
			}
		}
	}
}
