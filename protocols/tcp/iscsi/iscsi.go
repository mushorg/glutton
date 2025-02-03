package iscsi

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func handleISCSIMessage(buffer []byte) (iscsiRes, []byte, error) {
	msg := iscsiMsg{}
	r := bytes.NewReader(buffer)
	if err := binary.Read(r, binary.BigEndian, &msg); err != nil {
		return iscsiRes{}, nil, fmt.Errorf("Error reading iSCSI message: %v", err)
	}

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

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, res); err != nil {
		return iscsiRes{}, nil, fmt.Errorf("Failed to write response: %v", err)
	}
	return res, buf.Bytes(), nil
}
