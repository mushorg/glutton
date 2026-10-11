package banners

import "encoding/binary"

const (
	tnsHeaderLen     = 8
	tnsConnectMinLen = 34 // header through the connect flags
	tnsTypeConnect   = 0x01
	tnsTypeRefuse    = 0x04
	// TNS versions sent by Oracle 8i (300) through 23ai (319) clients.
	tnsMinVersion = 0x012c
	tnsMaxVersion = 0x013f
)

// tnsRefuseData is what an Oracle 19c listener answers to a CONNECT whose
// connect descriptor names no SERVICE_NAME or SID (ORA-12504). VSNNUM
// 318767104 is 0x13000000, version 19.0.0.0.0; nmap reads it as the
// oracle-tns version.
const tnsRefuseData = "(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=12504)" +
	"(ERROR_STACK=(ERROR=(CODE=12504)(EMFI=4))))"

// isTNSConnect reports whether data starts with an Oracle TNS CONNECT packet:
// type 0x01, a packet length that fits the segment, a known protocol version
// and a connect descriptor inside the packet.
func isTNSConnect(data []byte) bool {
	if len(data) < tnsConnectMinLen || data[4] != tnsTypeConnect {
		return false
	}
	pktLen := int(binary.BigEndian.Uint16(data[0:2]))
	if pktLen < tnsConnectMinLen || pktLen > len(data) {
		return false
	}
	version := binary.BigEndian.Uint16(data[8:10])
	compat := binary.BigEndian.Uint16(data[10:12])
	if version < tnsMinVersion || version > tnsMaxVersion || compat > version {
		return false
	}
	dataLen := int(binary.BigEndian.Uint16(data[24:26]))
	dataOff := int(binary.BigEndian.Uint16(data[26:28]))
	if dataLen == 0 || dataOff < tnsConnectMinLen || dataOff+dataLen > pktLen {
		return false
	}
	return data[dataOff] == '('
}

// tnsRefuse builds a TNS REFUSE packet: header with packet type 0x04, then
// user reason 0x22, system reason 0, the data length and the refuse data.
func tnsRefuse(refuse string) []byte {
	b := make([]byte, tnsHeaderLen+4+len(refuse))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(b)))
	b[4] = tnsTypeRefuse
	b[8] = 0x22
	binary.BigEndian.PutUint16(b[10:12], uint16(len(refuse)))
	copy(b[12:], refuse)
	return b
}
