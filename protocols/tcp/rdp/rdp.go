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

const (
	// X.224 TPDU type in the high nibble of the byte after LI (ITU-T X.224).
	TPDUConnectionRequest = 0xe0
	TPDUConnectionConfirm = 0xd0
	TPDUData              = 0xf0
	tpduTypeMask          = 0xf0
	rdpNegReqType         = 0x01
	rdpNegRspType         = 0x02

	// Selected/requested protocol flags (MS-RDPBCGR 2.2.1.1.1).
	ProtocolRDP    uint32 = 0x0
	ProtocolSSL    uint32 = 0x1
	ProtocolHybrid uint32 = 0x2
)

// RequestedMask returns the protocol bitmask from the CR's RDP_NEG_REQ, or 0
// when there is none.
func RequestedMask(pdu ConnectionRequestPDU) uint32 {
	if !HasRDPNegReq(pdu) {
		return 0
	}
	return binary.LittleEndian.Uint32(pdu.RDPNegReq.RequestedProtocols[:])
}

// SelectProtocol picks the single protocol a server answers with
// (MS-RDPBCGR 2.2.1.2.1 allows exactly one): CredSSP if offered, else TLS,
// else standard RDP security.
func SelectProtocol(requested uint32) uint32 {
	switch {
	case requested&ProtocolHybrid != 0:
		return ProtocolHybrid
	case requested&ProtocolSSL != 0:
		return ProtocolSSL
	default:
		return ProtocolRDP
	}
}

// ParseTKIPHeader reads the 4-byte TPKT header. It is safe on short slices.
func ParseTKIPHeader(data []byte) TKIPHeader {
	var header TKIPHeader
	if len(data) >= 1 {
		header.Version = data[0]
	}
	if len(data) >= 2 {
		header.Reserved = data[1]
	}
	if len(data) >= 4 {
		copy(header.Length[:], data[2:4])
	}
	return header
}

// TPDUType returns the X.224 TPDU type/credit byte, or 0 if the slice is too short.
func TPDUType(data []byte) byte {
	if len(data) < 6 {
		return 0
	}
	return data[5]
}

// IsConnectionRequest reports an X.224 Connection Request TPDU (type 0xE).
func IsConnectionRequest(data []byte) bool {
	return TPDUType(data)&tpduTypeMask == TPDUConnectionRequest
}

// IsDataTPDU reports an X.224 Data TPDU (type 0xF).
func IsDataTPDU(data []byte) bool {
	return TPDUType(data)&tpduTypeMask == TPDUData
}

// HasRDPNegReq reports whether the CR carried TYPE_RDP_NEG_REQ (0x01).
func HasRDPNegReq(pdu ConnectionRequestPDU) bool {
	return pdu.RDPNegReq.Type == rdpNegReqType
}

// ConnectionConfirm builds the X.224 CC. With includeNegRsp it carries an
// RDP_NEG_RSP naming selected (see SelectProtocol).
func ConnectionConfirm(cr CRTPDU, includeNegRsp bool, selected uint32) (TKIPHeader, []byte, error) {
	if !includeNegRsp {
		// MS-RDPBCGR 2.2.1.2: 11-byte CC, X.224 LI=6, no rdpNegData.
		cc := []byte{
			0x03, 0x00, 0x00, 0x0b,
			0x06, TPDUConnectionConfirm,
			cr.SrcRef[0], cr.SrcRef[1],
			0x00, 0x00,
			0x00,
		}
		return ParseTKIPHeader(cc), cc, nil
	}
	cc := ConnectionConfirmPDU{
		Header: TKIPHeader{
			Version: 3,
		},
		TPDU: CCTPDU{
			// LI excludes itself: 6-byte fixed CC header plus the 8-byte RDP_NEG_RSP.
			// MS-RDPBCGR 2.2.1.2: 14 when rdpNegData is present, 6 when it is not.
			Length: 14,
			CCCDT:  TPDUConnectionConfirm,
			DstRef: cr.SrcRef,
		},
		Response: NegotiationResponse{
			Type: rdpNegRspType,
		},
	}
	binary.LittleEndian.PutUint32(cc.Response.SelectedProtocol[:], selected)
	binary.LittleEndian.PutUint16(cc.Response.Length[:], 8)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, cc); err != nil {
		return TKIPHeader{}, nil, err
	}
	// TPKT length is the whole PDU, written big-endian.
	binary.BigEndian.PutUint16(cc.Header.Length[:], uint16(buf.Len()))
	binary.BigEndian.PutUint16(buf.Bytes()[2:4], uint16(buf.Len()))
	return cc.Header, buf.Bytes(), nil
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

	rest := buffer.Bytes()
	if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
		pdu.Data = append([]byte(nil), rest[:i]...)
		rest = rest[i+2:]
	}
	if len(rest) >= 8 && rest[0] == rdpNegReqType {
		if err := binary.Read(bytes.NewReader(rest[:8]), binary.LittleEndian, &pdu.RDPNegReq); err != nil {
			return pdu, err
		}
	}
	return pdu, nil
}
