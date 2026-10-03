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
	uid    uint16
	tid    uint16
}

func (ss *smbServer) write(header smb.SMBHeader, data []byte) error {
	framed := smb.WrapSessionMessage(data)
	_, err := ss.conn.Write(framed)
	if err != nil {
		return err
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "write",
		Header:    header,
		Payload:   framed,
	})
	return nil
}

func (ss *smbServer) nextUID() uint16 {
	ss.uid++
	return ss.uid
}

func (ss *smbServer) nextTID() uint16 {
	ss.tid++
	return ss.tid
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
		if n <= 0 || n >= maxBufferSize {
			continue
		}

		raw := make([]byte, n)
		copy(raw, buffer[:n])
		logger.Debug("SMB Payload", slog.String("payload", hex.Dump(raw)), slog.String("protocol", "smb"))

		frameStart := smb.FrameOffset(raw)
		frame := append([]byte(nil), raw[frameStart:]...)

		smbBuf, err := smb.ValidateData(raw)
		if err != nil {
			return err
		}
		// Snapshot full SMB PDU before ParseHeader consumes the 32-byte header.
		smbPDU := append([]byte(nil), smbBuf.Bytes()...)

		header := smb.SMBHeader{}
		if err := smb.ParseHeader(smbBuf, &header); err != nil {
			return err
		}

		payload := frame
		if len(payload) < len(smbPDU) {
			payload = smbPDU
		}
		server.events = append(server.events, parsedSMB{
			Direction: "read",
			Header:    header,
			Payload:   payload,
		})

		logger.Debug("SMB Header", slog.Any("header", header), slog.String("protocol", "smb"))

		var (
			responseHeader smb.SMBHeader
			resp           []byte
		)
		switch header.Command {
		case 0x72: // SMB_COM_NEGOTIATE
			var dialects []byte
			if req, err := smb.ParseNegotiateProtocolRequest(smbBuf, header); err == nil {
				dialects = req.Data.DialectString
			}
			responseHeader, resp, err = smb.MakeNegotiateProtocolResponse(header, dialects)
			if err != nil {
				return err
			}
		case 0x73: // SMB_COM_SESSION_SETUP_ANDX
			responseHeader, resp, err = smb.MakeSessionSetupAndXResponse(header, server.nextUID())
			if err != nil {
				return err
			}
		case 0x75: // SMB_COM_TREE_CONNECT_ANDX
			share := smb.TreeConnectShare(header, smbBuf.Bytes())
			responseHeader, resp, err = smb.MakeTreeConnectAndXResponse(header, server.nextTID(), share)
			if err != nil {
				return err
			}
		case 0x71: // SMB_COM_TREE_DISCONNECT
			responseHeader, resp, err = smb.MakeHeaderResponse(header)
			if err != nil {
				return err
			}
		case 0x74: // SMB_COM_LOGOFF_ANDX
			responseHeader, resp, err = smb.MakeHeaderResponse(header)
			if err != nil {
				return err
			}
		case 0x32: // SMB_COM_TRANSACTION2
			setup, setupOK := smb.Trans2Setup(smbBuf.Bytes())
			responseHeader, resp, err = smb.MakeComTransaction2Reply(header, setup, setupOK)
			if err != nil {
				return err
			}
		case 0x25: // SMB_COM_TRANSACTION
			responseHeader, resp, err = smb.MakeComTransactionResponse(header)
			if err != nil {
				return err
			}
		default:
			continue
		}
		if err := server.write(responseHeader, resp); err != nil {
			return err
		}
	}
	return nil
}
