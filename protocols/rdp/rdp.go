package rdp

import (
	"bytes"
	"encoding/binary"
)

// TKIPHeader see http://go.microsoft.com/fwlink/?LinkId=90541 section 8
type TKIPHeader struct {
	Version  byte
	Reserved byte
	Length   [2]byte
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

type NegotiationResponse struct {
	Type             byte
	Flags            byte
	Length           [2]byte
	SelectedProtocol [4]byte
}

type ConnectionConfirmPDU struct {
	Header   TKIPHeader
	TPDU     CCTPDU
	Response NegotiationResponse
}

func ConnectionConfirm(cr CRTPDU) (TKIPHeader, []byte, error) {
	cc := ConnectionConfirmPDU{
		Header: TKIPHeader{
			Version: 3,
		},
		TPDU: CCTPDU{
			Length: 6,
			CCCDT:  0xd, // 1101-xxxx
			DstRef: cr.DstRef,
			SrcRef: cr.SrcRef,
		},
		Response: NegotiationResponse{
			Type:             0x02,
			SelectedProtocol: [4]byte{0x3},
		},
	}
	binary.BigEndian.PutUint16(cc.Header.Length[:], 19)
	binary.LittleEndian.PutUint16(cc.Response.Length[:], 8)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, cc)
	return cc.Header, buf.Bytes(), err
}

// ParsePDU takes raw data and parses into struct
func ParseCRPDU(data []byte) (ConnectionRequestPDU, error) {
	pdu := ConnectionRequestPDU{}
	buffer := bytes.NewBuffer(data)
	if err := binary.Read(buffer, binary.LittleEndian, &pdu.Header); err != nil {
		return pdu, err
	}

	// I wonder if we should be more lenient here
	if len(data) != int(binary.BigEndian.Uint16(pdu.Header.Length[:])) {
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
