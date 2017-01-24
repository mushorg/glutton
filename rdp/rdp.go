package rdp

import (
	"bytes"
	"encoding/binary"
)

// TKIPHeader see http://go.microsoft.com/fwlink/?LinkId=90541 section 8
type TKIPHeader struct {
	Version  byte
	Reserved byte
	MSLength byte
	LSLength byte
}

// TPDU see http://go.microsoft.com/fwlink/?LinkId=90588 section 13.3
type TPDU struct {
	Length                byte
	ConnectionRequestCode byte
	DstRef                [2]byte
	SrcRef                [2]byte
	ClassOption           byte
}

type RDPNegReq struct {
	Type               byte
	Flags              byte
	Length             [2]byte
	RequestedProtocols [4]byte
}

type PDU struct {
	Header    TKIPHeader
	TPDU      TPDU
	Data      []byte
	RDPNegReq RDPNegReq
}

// ParsePDU takes raw data and parses into struct
func ParsePDU(data []byte) (pdu PDU, err error) {
	pdu = PDU{}
	buffer := bytes.NewBuffer(data)
	err = binary.Read(buffer, binary.LittleEndian, &pdu.Header)
	if err != nil {
		return
	}
	if len(data) != int(pdu.Header.LSLength) {
		return
	}
	err = binary.Read(buffer, binary.LittleEndian, &pdu.TPDU)
	if err != nil {
		return
	}
	pdu.Data = make([]byte, pdu.TPDU.Length-7-7)
	err = binary.Read(buffer, binary.LittleEndian, &pdu.Data)
	if err != nil {
		return
	}
	err = binary.Read(buffer, binary.LittleEndian, &pdu.RDPNegReq)
	if err != nil {
		return
	}
	return
}
