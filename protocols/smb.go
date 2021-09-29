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
func HandleSMB(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
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
			logger.Info(fmt.Sprintf("SMB payload:\n%s", hex.Dump(buffer[0:n])))
			buffer, err := smb.ValidateData(buffer[0:n])
			if err != nil {
				return err
			}
			header := smb.SMBHeader{}
			err = smb.ParseHeader(buffer, &header)
			if err != nil {
				return err
			}
			logger.Info(fmt.Sprintf("SMB header: %+v", header))
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
