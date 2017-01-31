package tds

import (
	"bytes"
	"encoding/binary"
)

type Header struct {
	Type     uint8
	Status   uint8
	Length   uint16
	SPID     uint16
	PacketID uint8
	Window   byte
}

type PreLogin struct {
	TokenType byte
}

type Login struct {
	Length        [4]byte
	TDSVersion    [4]byte
	PacketSize    [4]byte
	ClientProgVer [4]byte
	ClientPID     [4]byte
	ConnectionID  [4]byte
	OptionFlags1  byte
	OptionFlags2  byte
	TypeFlags     byte
	OptionFlags3  byte
	ClientTimZone [4]byte
	ClientLCID    [4]byte
}

type TDS struct {
	Header     Header
	PacketData interface{}
}

func ParseHeader(buffer *bytes.Buffer) (header Header, err error) {
	header = Header{}
	err = binary.Read(buffer, binary.BigEndian, &header)
	if err != nil {
		return
	}
	return
}

func parsePreLogin(buffer *bytes.Buffer) (packetData PreLogin, err error) {
	packetData = PreLogin{}
	err = binary.Read(buffer, binary.BigEndian, &packetData)
	return
}

func parseLogin(buffer *bytes.Buffer) (packetData Login, err error) {
	packetData = Login{}
	err = binary.Read(buffer, binary.BigEndian, &packetData)
	return
}

func ParseTDS(data []byte) (parsed TDS, err error) {
	buffer := bytes.NewBuffer(data)
	header, err := ParseHeader(buffer)
	if err != nil {
		return
	}
	if header.Length-8 <= 0 {
		return
	}
	switch header.Type {
	case 16:
		parsed.PacketData, err = parsePreLogin(buffer)
	case 18:
		parsed.PacketData, err = parseLogin(buffer)
	}
	if err != nil {
		return
	}

	return
}
