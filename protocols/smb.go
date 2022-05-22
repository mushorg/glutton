package protocols

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/smb"
	"go.uber.org/zap"
)

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close SMB connection", zap.Error(err))
		}
	}()

	buffer := make([]byte, 1024)
	for {
		h.UpdateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err != nil && n <= 0 {
			return err
		}
		if n > 0 && n < 1024 {
			logger.Debug(fmt.Sprintf("SMB payload:\n%s", hex.Dump(buffer[0:n])))
			buffer, err := smb.ValidateData(buffer[0:n])
			if err != nil {
				return err
			}

			md, err := h.MetadataByConnection(conn)
			if err != nil {
				return err
			}
			if err := h.Produce(conn, md, buffer.Bytes()); err != nil {
				logger.Error("failed to produce message", zap.String("protocol", "smb"), zap.Error(err))
			}

			header := smb.SMBHeader{}
			err = smb.ParseHeader(buffer, &header)
			if err != nil {
				return err
			}
			logger.Debug(fmt.Sprintf("SMB header: %+v", header))
			switch header.Command {
			case 0x72, 0x73, 0x75:
				resp, err := smb.MakeNegotiateProtocolResponse(header)
				if err != nil {
					return err
				}
				if _, err := conn.Write(resp); err != nil {
					return err
				}
			case 0x32:
				resp, err := smb.MakeComTransaction2Response(header)
				if err != nil {
					return err
				}
				if _, err := conn.Write(resp); err != nil {
					return err
				}
			case 0x25:
				resp, err := smb.MakeComTransactionResponse(header)
				if err != nil {
					return err
				}
				if _, err := conn.Write(resp); err != nil {
					return err
				}
			}
		}
	}
}
