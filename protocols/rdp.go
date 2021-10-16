package protocols

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/rdp"
)

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Sprintf("[rdp     ]  error: %v", err))
		}
	}()

	buffer := make([]byte, 1024)
	for {
		h.UpdateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err != nil && n <= 0 {
			logger.Error(fmt.Sprintf("[rdp     ] error: %v", err))
			return err
		}
		if n > 0 && n < 1024 {
			logger.Info(fmt.Sprintf("[rdp     ] \n%s", hex.Dump(buffer[0:n])))
			pdu, err := rdp.ParseCRPDU(buffer[0:n])
			if err != nil {
				return err
			}
			logger.Info(fmt.Sprintf("[rdp     ] req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				logger.Info(fmt.Sprintf("[rdp     ] data: %s", string(pdu.Data)))
			}
			resp := rdp.ConnectionConfirm()
			logger.Info(fmt.Sprintf("[rdp     ]resp pdu: %+v", resp))
			if _, err = conn.Write(resp); err != nil {
				return err
			}
		}
	}
}
