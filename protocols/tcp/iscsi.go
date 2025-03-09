package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/iscsi"
)

type ParsedIscsi struct {
	Direction string         `json:"direction,omitempty"`
	Message   iscsi.IscsiMsg `json:"message,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
}
type iscsiServer struct {
	events []ParsedIscsi
	conn   net.Conn
}

// iSCSI messages contain a 48 byte header. The first byte contains the Opcode(Operation Code) which defines the type of operation that is to be performed.
func (si *iscsiServer) handleISCSIMessage(conn net.Conn, md connection.Metadata, buffer []byte, logger interfaces.Logger, h interfaces.Honeypot, n int) error {
	defer func() {
		if err := h.ProduceTCP("iscsi", conn, md, buffer, si.events); err != nil {
			logger.Error("failed to produce message", slog.String("handler", "iscsi"), producer.ErrAttr(err))
		}
	}()

	msg, res, _, err := iscsi.ParseISCSIMessage(buffer)
	if err != nil {
		return err
	}

	si.events = append(si.events, ParsedIscsi{
		Direction: "read",
		Message:   msg,
		Payload:   buffer[:n],
	})

	logger.Info("received iSCSI message", slog.String("opcode", string(msg.Opcode)), slog.String("handler", "iscsi"))

	if err := binary.Write(conn, binary.BigEndian, res); err != nil {
		return err
	}

	si.events = append(si.events, ParsedIscsi{
		Direction: "write",
		Message:   res,
		Payload:   buffer[:],
	})

	return nil
}

func HandleISCSI(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Error("failed to close iSCSI connection", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
		}
	}()

	server := &iscsiServer{
		events: []ParsedIscsi{},
		conn:   conn,
	}

	buffer := make([]byte, 4096)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Error("failed to set connection timeout", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			break
		}
		n, err := conn.Read(buffer)
		if err != nil && err != io.ErrUnexpectedEOF {
			logger.Error("failed to read from connection", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			break
		}
		if err == io.ErrUnexpectedEOF {
			logger.Error("failed to read the complete file", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
		}
		err = server.handleISCSIMessage(conn, md, buffer, logger, h, n)
		if err != nil {
			logger.Error("failed to handle iSCSI message", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			break
		}
	}
	return nil
}
