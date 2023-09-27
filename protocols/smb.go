package protocols

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/smb"
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
func HandleSMB(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	server := &smbServer{
		events: []parsedSMB{},
		conn:   conn,
	}
	defer func() {
		md, err := h.MetadataByConnection(conn)
		if err != nil {
			logger.Error("failed to get metadata", zap.Error(err))
		}
		if err := h.Produce("smb", conn, md, firstOrEmpty[parsedSMB](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce message", zap.String("protocol", "smb"), zap.Error(err))
		}

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
