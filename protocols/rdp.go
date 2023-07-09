package protocols

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/rdp"
	"go.uber.org/zap"
)

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Sprintf("[rdp     ]  error: %v", err))
		}
	}()

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return fmt.Errorf("failed to get metadata: %w", err)
	}

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
			if err := h.Produce("rdp", conn, md, buffer[0:n], pdu); err != nil {
				logger.Error("failed to produce message", zap.String("protocol", "rdp"), zap.Error(err))
			}
			logger.Info(fmt.Sprintf("[rdp     ] req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				logger.Info(fmt.Sprintf("[rdp     ] data: %s", string(pdu.Data)))
			}
			resp, err := rdp.ConnectionConfirm(pdu.TPDU)
			if err != nil {
				return err
			}
			logger.Info(fmt.Sprintf("[rdp     ] resp pdu: %+v", resp))
			if _, err = conn.Write(resp); err != nil {
				return err
			}
		}
	}
}
