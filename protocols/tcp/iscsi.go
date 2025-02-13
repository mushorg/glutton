package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type iscsiMsg struct {
	Opcode  uint8
	Flags   uint8
	TaskTag uint32
	Data    uint32
	CID     uint32
	LUN     uint64
}

type parsedIscsi struct {
	Direction string   `json:"direction,omitempty"`
	Message   iscsiMsg `json:"message,omitempty"`
	Payload   []byte   `json:"payload,omitempty"`
}
type iscsiServer struct {
	events []parsedIscsi
	conn   net.Conn
}

// iSCSI messages contain a 48 byte header. The first byte contains the Opcode(Operation Code) which defines the type of operation that is to be performed.
func handleISCSIMessage(conn net.Conn, md connection.Metadata, buffer []byte, logger interfaces.Logger, h interfaces.Honeypot, server *iscsiServer, n int) error {

	defer func() {
		if err := h.ProduceTCP("iscsi", conn, md, buffer, server.events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "iscsi"))
		}
	}()

	msg := iscsiMsg{}
	r := bytes.NewReader(buffer)
	if err := binary.Read(r, binary.BigEndian, &msg); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("new iSCSI packet with opcode: %d, task tag: %d", msg.Opcode, msg.TaskTag), slog.String("handler", "iscsi"))

	// Parse different iSCSI messages based on their opCode.
	var res iscsiMsg
	switch msg.Opcode {
	case 0x03:
		res = iscsiMsg{
			Opcode:  0x23, // Login response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
		}
	case 0x01: //Initiator SCSI Command
		res = iscsiMsg{
			Opcode:  0x21, // Target SCSI response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    8, //Can vary
			CID:     msg.CID,
			LUN:     msg.LUN,
		}
	case 0x06: // Logout Request
		res = iscsiMsg{
			Opcode:  0x26, // Logout Response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
		}
	default:
		res = iscsiMsg{
			Opcode:  0x00,
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
		}
	}
	server.events = append(server.events, parsedIscsi{
		Direction: "write",
		Message:   msg,
		Payload:   buffer[:n],
	})

	if err := binary.Write(conn, binary.BigEndian, res); err != nil {
		return err
	}
	return nil
}

func HandleISCSI(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("[iscsi    ] error: %v", err))
		}
	}()

	server := &iscsiServer{
		events: []parsedIscsi{},
		conn:   conn,
	}

	buffer := make([]byte, 4096)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Error(fmt.Sprintf("[iscsi	] error : %v", err))
			break
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Error(fmt.Sprintf("[iscsi	] error : %v", err))
			break
		}

		msg := iscsiMsg{}

		if err := binary.Read(bytes.NewReader(buffer[:n]), binary.BigEndian, &msg); err != nil {
			logger.Error("Failed to read message", producer.ErrAttr(err), slog.String("handler", "iscsi"))
			break
		}

		server.events = append(server.events, parsedIscsi{
			Direction: "read",
			Message:   msg,
			Payload:   buffer[:n],
		})

		err = handleISCSIMessage(conn, md, buffer, logger, h, server, n)
		logger.Error(fmt.Sprintf("[iscsi	] error : %v", err))
	}
	return nil
}
