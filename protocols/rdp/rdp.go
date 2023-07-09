package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TKIPHeader see http://go.microsoft.com/fwlink/?LinkId=90541 section 8
type TKIPHeader struct {
	Version  byte
	Reserved byte
	MSLength byte
	LSLength byte
}

// CRTPDU see http://go.microsoft.com/fwlink/?LinkId=90588 section 13.3
type CRTPDU struct {
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

type ConnectionRequestPDU struct {
	Header    TKIPHeader
	TPDU      CRTPDU
	Data      []byte
	RDPNegReq RDPNegReq
}

// CCTPDU Connection Confirm see http://go.microsoft.com/fwlink/?LinkId=90588 section 13.3
type CCTPDU struct {
	Length      byte // header length including parameters
	CCCDT       byte
	DstRef      [2]byte
	SrcRef      [2]byte
	ClassOption byte
}

type ConnectionConfirmPDU struct {
	Header TKIPHeader
	TPDU   CCTPDU
}

func ConnectionConfirm(cr CRTPDU) ([]byte, error) {
	cc := ConnectionConfirmPDU{
		Header: TKIPHeader{
			Version:  3,
			LSLength: 11,
		},
		TPDU: CCTPDU{
			Length: 6,
			CCCDT:  208, // 1101-xxxx
			DstRef: cr.DstRef,
			SrcRef: cr.SrcRef,
		},
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, cc)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	return buf.Bytes(), nil
}

// ParsePDU takes raw data and parses into struct
func ParseCRPDU(data []byte) (ConnectionRequestPDU, error) {
	pdu := ConnectionRequestPDU{}
	buffer := bytes.NewBuffer(data)
	if err := binary.Read(buffer, binary.LittleEndian, &pdu.Header); err != nil {
		return pdu, err
	}

	// I wonder if we should be more lenient here
	if len(data) != int(pdu.Header.LSLength) {
		return pdu, nil
	}
	if err := binary.Read(buffer, binary.LittleEndian, &pdu.TPDU); err != nil {
		return pdu, err
	}

	// Not sure if this is the best way to get the offset...
	offset := bytes.Index(data, []byte("\r\n"))
	switch {
	case offset < 4:
		return pdu, nil
	case offset < 4+7:
		if offset-4 == 0 {
			return pdu, nil
		}
		pdu.Data = make([]byte, offset-4)
	default:
		if offset-4-7 <= 0 {
			return pdu, nil
		}
		pdu.Data = make([]byte, offset-4-7)
	}

	if err := binary.Read(buffer, binary.LittleEndian, &pdu.Data); err != nil {
		return pdu, err
	}
	if buffer.Len() >= 8 {
		if err := binary.Read(buffer, binary.LittleEndian, &pdu.RDPNegReq); err != nil {
			return pdu, err
		}
	}
	return pdu, nil
}
