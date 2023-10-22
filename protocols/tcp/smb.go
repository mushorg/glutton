package tcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/smb"
	"go.uber.org/zap"
)

type parsedSMB struct {
	Direction string        `json:"direction,omitempty"`
	Header    smb.SMBHeader `json:"header,omitempty"`
	Payload   []byte        `json:"payload,omitempty"`
}

type smbServer struct {
	events []parsedSMB
	conn   net.Conn
}

func (ss *smbServer) write(header smb.SMBHeader, data []byte) error {
	_, err := ss.conn.Write(data)
	if err != nil {
		return err
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "write",
		Header:    header,
		Payload:   data,
	})
	return nil
}

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &smbServer{
		events: []parsedSMB{},
		conn:   conn,
	}
	defer func() {
		if err := h.ProduceTCP("smb", conn, md, helpers.FirstOrEmpty[parsedSMB](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce message", zap.String("protocol", "smb"), zap.Error(err))
		}

		if err := conn.Close(); err != nil {
			logger.Error("failed to close SMB connection", zap.Error(err))
		}
	}()

	buffer := make([]byte, 4096)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		if n > 0 && n < 4096 {
			logger.Debug(fmt.Sprintf("SMB payload:\n%s", hex.Dump(buffer[0:n])))
			buffer, err := smb.ValidateData(buffer[0:n])
			if err != nil {
				return err
			}

			header := smb.SMBHeader{}
			err = smb.ParseHeader(buffer, &header)
			if err != nil {
				return err
			}

			server.events = append(server.events, parsedSMB{
				Direction: "read",
				Header:    header,
				Payload:   buffer.Bytes(),
			})

			logger.Debug(fmt.Sprintf("SMB header: %+v", header))
			switch header.Command {
			case 0x72, 0x73, 0x75:
				responseHeader, resp, err := smb.MakeNegotiateProtocolResponse(header)
				if err != nil {
					return err
				}
				if err := server.write(responseHeader, resp); err != nil {
					return err
				}
			case 0x32:
				responseHeader, resp, err := smb.MakeComTransaction2Response(header)
				if err != nil {
					return err
				}
				if err := server.write(responseHeader, resp); err != nil {
					return err
				}
			case 0x25:
				responseHeader, resp, err := smb.MakeComTransactionResponse(header)
				if err != nil {
					return err
				}
				if err := server.write(responseHeader, resp); err != nil {
					return err
				}
			}
		}
	}
}
