package tcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
)

type parsedRDP struct {
	Direction string         `json:"direction,omitempty"`
	Header    rdp.TKIPHeader `json:"header,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
}

type rdpServer struct {
	events []parsedRDP
	conn   net.Conn
}

func (rs *rdpServer) write(header rdp.TKIPHeader, data []byte) error {
	rs.events = append(rs.events, parsedRDP{
		Header:    header,
		Direction: "write",
		Payload:   data,
	})
	_, err := rs.conn.Write(data)
	return err
}

// HandleRDP takes a net.Conn and does basic RDP communication
func HandleRDP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rdpServer{
		events: []parsedRDP{},
		conn:   conn,
	}
	defer func() {
		if err := h.ProduceTCP("rdp", conn, md, helpers.FirstOrEmpty[parsedRDP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rdp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RDP connection", slog.String("protocol", "rdp"), producer.ErrAttr(err))
		}
	}()

	buffer := make([]byte, maxBufferSize)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil && n <= 0 {
			logger.Debug("Failed to read from connection", slog.String("protocol", "rdp"), producer.ErrAttr(err))
			return nil
		}
		if n > 0 && n < 1024 {
			logger.Debug(fmt.Sprintf("rdp \n%s", hex.Dump(buffer[0:n])))
			pdu, err := rdp.ParseCRPDU(buffer[0:n])
			if err != nil {
				return err
			}
			server.events = append(server.events, parsedRDP{
				Direction: "read",
				Header:    pdu.Header,
				Payload:   buffer[0:n],
			})
			logger.Debug(fmt.Sprintf("rdp req pdu: %+v", pdu))
			if len(pdu.Data) > 0 {
				logger.Debug(fmt.Sprintf("rdp data: %s", string(pdu.Data)))
			}
			header, resp, err := rdp.ConnectionConfirm(pdu.TPDU)
			if err != nil {
				return err
			}
			logger.Debug(fmt.Sprintf("rdp resp pdu: %+v", resp))
			if err := server.write(header, resp); err != nil {
				return err
			}
		}
	}
}
