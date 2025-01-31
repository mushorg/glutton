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

type iscsiRes struct {
	Opcode  uint8
	Flags   uint8
	TaskTag uint32
	Data    uint32
	CID     uint32
	LUN     uint64
	Status  uint8
}

type iscsiRequest struct {
	Msg iscsiMsg
	Res iscsiRes
}

type iscsiServer struct {
	events []iscsiRequest
	conn   net.Conn
}

// iSCSI messages contain a 48 byte header. The first byte contains the Opcode(Operation Code) which defines the type of operation that is to be performed.
func handleISCSIMessage(conn net.Conn, md connection.Metadata, buffer []byte, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &iscsiServer{
		events: []iscsiRequest{},
		conn:   conn,
	}

	defer func() {
		if err := h.ProduceTCP("iscsi", conn, md, buffer, server.events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "iscsi"))
		}
	}()

	msg := iscsiMsg{}
	r := bytes.NewReader(buffer)
	if err := binary.Read(r, binary.BigEndian, &msg); err != nil {
		logger.Error("Error reading iSCSI message. Error : %v", err)
		return err
	}

	logger.Info(fmt.Sprintf("new iSCSI packet with opcode: %d, task tag: %d", msg.Opcode, msg.TaskTag), slog.String("handler", "iscsi"))

	// Parse different iSCSI messages based on their opCode.
	var res iscsiRes
	switch msg.Opcode {
	case 0x03:
		res = iscsiRes{
			Opcode:  0x23, // Login response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
			Status:  0x00,
		}
	case 0x01: //Initiator SCSI Command
		res = iscsiRes{
			Opcode:  0x21, // Target SCSI response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    8, //Can vary
			CID:     msg.CID,
			LUN:     msg.LUN,
			Status:  0x00,
		}
	case 0x06: // Logout Request
		res = iscsiRes{
			Opcode:  0x26, // Logout Response
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
			Status:  0x00,
		}
	default:
		res = iscsiRes{
			Opcode:  0x00,
			Flags:   0x00,
			TaskTag: msg.TaskTag,
			Data:    0,
			CID:     msg.CID,
			LUN:     msg.LUN,
			Status:  0x01,
		}
	}
	server.events = append(server.events, iscsiRequest{
		Msg: msg,
		Res: res,
	})

	if err := binary.Write(conn, binary.BigEndian, res); err != nil {
		logger.Error("Failed to write buffer", producer.ErrAttr(err), slog.String("handler", "iscsi"))
		return err
	}
	return nil
}

// HandleISCSI handles a ISCSI connection
func HandleISCSI(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("[iscsi    ] error: %v", err))
		}
	}()
	buffer := make([]byte, 4096)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		_, err := conn.Read(buffer)
		if err != nil {
			logger.Error(fmt.Sprintf("[iscsi	] error : %v", err))
			return err
		}
		handleISCSIMessage(conn, md, buffer, logger, h)
	}
}
