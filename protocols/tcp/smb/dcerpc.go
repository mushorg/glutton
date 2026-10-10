package smb

import (
	"encoding/binary"
	"fmt"
)

// MS-RPCE connection-oriented DCERPC. Glutton accepts the bind handshake so
// clients proceed to send their request, logs which interface and operation
// were called, and faults every request: it never emulates an RPC service, so
// the honeypot cannot act as a working backend.

const (
	dcerpcVersion      = 5
	dcerpcHeaderLen    = 16
	dcerpcPTypeRequest = 0x00
	dcerpcPTypeFault   = 0x03
	dcerpcPTypeBind    = 0x0b
	dcerpcPTypeBindAck = 0x0c

	dcerpcFlagFirst      = 0x01
	dcerpcFlagLast       = 0x02
	dcerpcFlagObjectUUID = 0x80

	// nca_s_fault_ndr — a generic, non-revealing fault for unimplemented calls.
	dcerpcFaultNDR = 0x000006f7
)

var dcerpcPTypeNames = map[byte]string{
	dcerpcPTypeRequest: "DCERPC_REQUEST",
	dcerpcPTypeFault:   "DCERPC_FAULT",
	dcerpcPTypeBind:    "DCERPC_BIND",
	dcerpcPTypeBindAck: "DCERPC_BIND_ACK",
}

// Exported PDU type codes for handlers dispatching on ParseDCERPCHeader.
const (
	PTypeRequest = dcerpcPTypeRequest
	PTypeBind    = dcerpcPTypeBind
)

// DCERPCName returns the PDU type mnemonic, or DCERPC_0xNN for unknowns.
func DCERPCName(ptype byte) string {
	if name, ok := dcerpcPTypeNames[ptype]; ok {
		return name
	}
	return fmt.Sprintf("DCERPC_0x%02X", ptype)
}

// DCERPCHeader is the common MS-RPCE PDU header.
type DCERPCHeader struct {
	PType    byte
	Flags    byte
	FragLen  uint16
	AuthLen  uint16
	CallID   uint32
	LittleEn bool
}

// ParseDCERPCHeader decodes the 16-byte common header. ok is false when the
// buffer is too short or the RPC major version is not 5.
func ParseDCERPCHeader(b []byte) (DCERPCHeader, bool) {
	if len(b) < dcerpcHeaderLen || b[0] != dcerpcVersion {
		return DCERPCHeader{}, false
	}
	// packed_drep[0] bit: 0x10 => little-endian integers (the common case).
	little := b[4]&0x10 != 0
	order := binary.ByteOrder(binary.LittleEndian)
	if !little {
		order = binary.BigEndian
	}
	return DCERPCHeader{
		PType:    b[2],
		Flags:    b[3],
		FragLen:  order.Uint16(b[8:10]),
		AuthLen:  order.Uint16(b[10:12]),
		CallID:   order.Uint32(b[12:16]),
		LittleEn: little,
	}, true
}

// BindContext is one presentation context from a bind request.
type BindContext struct {
	ContextID      uint16
	AbstractUUID   [16]byte
	AbstractVer    uint32
	TransferSyntax [20]byte // 16-byte UUID + 4-byte version
}

// InterfaceUUID formats the abstract-syntax UUID as a canonical GUID string
// (mixed-endian wire layout, as Windows interface IDs are written).
func (c BindContext) InterfaceUUID() string {
	return guidString(c.AbstractUUID)
}

// InterfaceVersion formats the abstract-syntax version as "major.minor".
func (c BindContext) InterfaceVersion() string {
	return fmt.Sprintf("%d.%d", c.AbstractVer&0xffff, c.AbstractVer>>16)
}

// ParseBind decodes the presentation contexts from a bind PDU (starting at the
// common header). ok is false when the PDU is malformed.
func ParseBind(pdu []byte) ([]BindContext, bool) {
	// header(16) + max_xmit(2) + max_recv(2) + assoc_group(4) = 24, then
	// p_context_elem: n_context_elem(1) + reserved(1) + reserved2(2) = 4.
	const listOff = dcerpcHeaderLen + 8
	if len(pdu) < listOff+4 {
		return nil, false
	}
	n := int(pdu[listOff])
	off := listOff + 4
	var out []BindContext
	for i := 0; i < n; i++ {
		// p_cont_id(2) + n_transfer_syn(1) + reserved(1) + abstract(20).
		if off+24 > len(pdu) {
			return nil, false
		}
		var ctx BindContext
		ctx.ContextID = binary.LittleEndian.Uint16(pdu[off : off+2])
		nSyn := int(pdu[off+2])
		copy(ctx.AbstractUUID[:], pdu[off+4:off+20])
		ctx.AbstractVer = binary.LittleEndian.Uint32(pdu[off+20 : off+24])
		off += 24
		if nSyn > 0 {
			if off+20 > len(pdu) {
				return nil, false
			}
			copy(ctx.TransferSyntax[:], pdu[off:off+20])
		}
		off += nSyn * 20
		out = append(out, ctx)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// BuildBindAck builds a bind_ack that accepts every presentation context with
// the client's transfer syntax, echoing callID and advertising secAddr (the
// named pipe), as a real server would.
func BuildBindAck(callID uint32, secAddr string, contexts []BindContext) []byte {
	sec := append([]byte(secAddr), 0)
	// sec_addr_len(2) + sec_addr, padded to a 4-byte boundary from the start
	// of the sec_addr_len field (which sits at offset 24 in the PDU).
	body := make([]byte, 0, 32+len(contexts)*24)
	body = append(body, 0xd0, 0x16)             // max_xmit_frag
	body = append(body, 0xd0, 0x16)             // max_recv_frag
	body = append(body, 0x4d, 0x00, 0x00, 0x00) // assoc_group_id
	var secLen [2]byte
	binary.LittleEndian.PutUint16(secLen[:], uint16(len(sec)))
	body = append(body, secLen[:]...)
	body = append(body, sec...)
	for (dcerpcHeaderLen+len(body))%4 != 0 {
		body = append(body, 0) // align the result list
	}
	body = append(body, byte(len(contexts)), 0, 0, 0) // n_results + reserved
	for _, c := range contexts {
		body = append(body, 0x00, 0x00) // result: acceptance
		body = append(body, 0x00, 0x00) // reason
		body = append(body, c.TransferSyntax[:]...)
	}
	return dcerpcFrame(dcerpcPTypeBindAck, callID, body)
}

// ParseRequest decodes opnum, context id, and stub data from a request PDU.
func ParseRequest(pdu []byte) (opnum, ctxID uint16, stub []byte, ok bool) {
	h, hok := ParseDCERPCHeader(pdu)
	if !hok || h.PType != dcerpcPTypeRequest {
		return 0, 0, nil, false
	}
	// alloc_hint(4) + p_cont_id(2) + opnum(2).
	const fixed = dcerpcHeaderLen + 8
	if len(pdu) < fixed {
		return 0, 0, nil, false
	}
	ctxID = binary.LittleEndian.Uint16(pdu[dcerpcHeaderLen+4 : dcerpcHeaderLen+6])
	opnum = binary.LittleEndian.Uint16(pdu[dcerpcHeaderLen+6 : dcerpcHeaderLen+8])
	stubOff := fixed
	if h.Flags&dcerpcFlagObjectUUID != 0 {
		stubOff += 16
	}
	if stubOff > len(pdu) {
		stubOff = len(pdu)
	}
	return opnum, ctxID, pdu[stubOff:], true
}

// BuildFault builds a fault PDU echoing callID with nca_s_fault_ndr.
func BuildFault(callID uint32) []byte {
	body := make([]byte, 16)
	// alloc_hint(4)=0, p_cont_id(2)=0, cancel_count(1)=0, reserved(1)=0.
	binary.LittleEndian.PutUint32(body[8:12], dcerpcFaultNDR) // status
	return dcerpcFrame(dcerpcPTypeFault, callID, body)
}

// dcerpcFrame prepends the common header (little-endian, first+last fragment)
// to body and fills frag_length.
func dcerpcFrame(ptype byte, callID uint32, body []byte) []byte {
	out := make([]byte, dcerpcHeaderLen+len(body))
	out[0] = dcerpcVersion
	out[1] = 0 // minor
	out[2] = ptype
	out[3] = dcerpcFlagFirst | dcerpcFlagLast
	out[4] = 0x10 // packed_drep: little-endian, ASCII, IEEE
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
	binary.LittleEndian.PutUint32(out[12:16], callID)
	copy(out[dcerpcHeaderLen:], body)
	return out
}

// guidString formats a 16-byte wire GUID (mixed-endian) as a canonical UUID.
func guidString(b [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10:16])
}
