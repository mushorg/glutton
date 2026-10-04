package tcp

import (
	"context"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/iscsi"
)

const maxISCSIMessages = 64

var iscsiOpcodeNames = map[uint8]string{
	0x01: "SCSI_COMMAND",
	0x03: "LOGIN_REQUEST",
	0x06: "LOGOUT_REQUEST",
	0x20: "NOP_IN",
	0x21: "SCSI_RESPONSE",
	0x23: "LOGIN_RESPONSE",
	0x26: "LOGOUT_RESPONSE",
}

type ParsedIscsi struct {
	Direction string         `json:"direction,omitempty"`
	Command   string         `json:"command,omitempty"`
	Message   iscsi.IscsiMsg `json:"message,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
}
type iscsiServer struct {
	events []ParsedIscsi
	conn   net.Conn
}

func iscsiCommand(opcode uint8) string {
	if name, ok := iscsiOpcodeNames[opcode]; ok {
		return name
	}
	return "UNKNOWN"
}

func (si *iscsiServer) handleISCSIMessage(buffer []byte, n int) error {
	msg, res, respBytes, err := iscsi.ParseISCSIMessage(buffer)
	if err != nil {
		return err
	}

	payload := make([]byte, n)
	copy(payload, buffer[:n])
	si.events = append(si.events, ParsedIscsi{
		Direction: "read",
		Command:   iscsiCommand(msg.Opcode),
		Message:   msg,
		Payload:   payload,
	})

	if _, err := si.conn.Write(respBytes); err != nil {
		return err
	}

	si.events = append(si.events, ParsedIscsi{
		Direction: "write",
		Command:   iscsiCommand(res.Opcode),
		Message:   res,
		Payload:   respBytes,
	})

	return nil
}

func HandleISCSI(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &iscsiServer{
		events: []ParsedIscsi{},
		conn:   conn,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("iscsi", conn, md, helpers.FirstOrEmpty[ParsedIscsi](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce message", slog.String("handler", "iscsi"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close iSCSI connection", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
		}
	}()

	buffer := make([]byte, 4096)
	i := 0
	for ; i < maxISCSIMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("failed to set connection timeout", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			break
		}
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logger.Debug("failed to read from connection", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			break
		}
		if err := server.handleISCSIMessage(buffer, n); err != nil {
			logger.Debug("failed to handle iSCSI message", slog.String("protocol", "iscsi"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			break
		}
	}
	if i >= maxISCSIMessages {
		endReason = connection.EndMaxFrames
	}
	return nil
}
