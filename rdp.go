package glutton

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/rdp"
)

// HandleRDP takes a net.Conn and does basic RDP communication
func (g *Glutton) HandleRDP(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[rdp     ]  error: %v", err))
		}
	}()

	buffer := make([]byte, 1024)
	for {
		g.updateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err != nil && n <= 0 {
			g.logger.Error(fmt.Sprintf("[rdp     ] error: %v", err))
			return err
		}
		if n > 0 && n < 1024 {
			g.logger.Info(fmt.Sprintf("[rdp     ] \n%s", hex.Dump(buffer[0:n])))
			pdu, err := rdp.ParseCRPDU(buffer[0:n])
			if err != nil {
				g.logger.Error(fmt.Sprintf("[rdp     ] error: %v", err))
			}
			g.logger.Info(fmt.Sprintf("[rdp     ] req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				g.logger.Info(fmt.Sprintf("[rdp     ] data: %s", string(pdu.Data)))
			}
			resp := rdp.ConnectionConfirm()
			g.logger.Info(fmt.Sprintf("[rdp     ]resp pdu: %+v", resp))
			conn.Write(resp)
		}
	}
}
