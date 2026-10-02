package tcp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/smb"
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
			logger.Error("Failed to produce message", slog.String("protocol", "smb"), producer.ErrAttr(err))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SMB connection", producer.ErrAttr(err), slog.String("protocol", "smb"))
		}
	}()

	buffer := make([]byte, maxBufferSize)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smb"), producer.ErrAttr(err))
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smb"), producer.ErrAttr(err))
			break
		}
		if n > 0 && n < maxBufferSize {
			logger.Debug("SMB Payload", slog.String("payload", hex.Dump(buffer[0:n])), slog.String("protocol", "smb"))
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

			logger.Debug("SMB Header", slog.Any("header", header), slog.String("protocol", "smb"))
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
	return nil
}
