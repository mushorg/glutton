// Package epm parses MS-RPCE endpoint mapper (EPM, interface
// e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0) request stubs and builds the
// replies Glutton sends on tcp/135. Only ept_lookup and ept_map are answered,
// and both report an empty endpoint database: the honeypot never hands out a
// real endpoint, so it cannot route a client to a working RPC service.
package epm

import (
	"encoding/binary"
	"fmt"
)

const (
	// UUID is the endpoint mapper interface id as formatted by
	// smb.BindContext.InterfaceUUID.
	UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"

	OpLookup = 2 // ept_lookup
	OpMap    = 3 // ept_map

	// StatusNotRegistered is EPT_S_NOT_REGISTERED, the status an endpoint
	// mapper returns when the lookup or map finds no (more) entries.
	StatusNotRegistered = 0x16c9a0d6

	contextHandleLen = 20 // attributes(4) + uuid(16)
	uuidLen          = 16
	ifIDLen          = 20 // uuid(16) + vers_major(2) + vers_minor(2)
)

var opNames = map[uint16]string{
	0: "ept_insert",
	1: "ept_delete",
	2: "ept_lookup",
	3: "ept_map",
	4: "ept_lookup_handle_free",
	5: "ept_inq_object",
	6: "ept_mgmt_delete",
}

// OpName returns the EPM operation name for opnum, or "" when unknown.
func OpName(opnum uint16) string {
	return opNames[opnum]
}

// Request is the decoded [in] part of an ept_lookup or ept_map stub.
type Request struct {
	// Max is max_ents (ept_lookup) or max_towers (ept_map): the size of the
	// [out] array the client reserved, echoed as its NDR max_count.
	Max uint32
	// Interface is the interface the client asks about: the Ifid of an
	// ept_lookup, or the floor-1 interface of an ept_map tower. Empty when
	// the client did not name one.
	Interface        string
	InterfaceVersion string
}

// ndrReader walks a little-endian NDR20 stub.
type ndrReader struct {
	b   []byte
	off int
	ok  bool
}

func (r *ndrReader) take(n int) []byte {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *ndrReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *ndrReader) align4() {
	if pad := (4 - r.off%4) % 4; pad > 0 {
		r.take(pad)
	}
}

// ParseLookup decodes an ept_lookup request stub.
func ParseLookup(stub []byte) (Request, bool) {
	r := &ndrReader{b: stub, ok: true}
	var req Request
	r.u32() // inquiry_type
	if r.u32() != 0 {
		r.take(uuidLen) // object
	}
	if r.u32() != 0 {
		if id := r.take(ifIDLen); id != nil {
			req.Interface = guidString(id[:uuidLen])
			req.InterfaceVersion = fmt.Sprintf("%d.%d",
				binary.LittleEndian.Uint16(id[16:18]), binary.LittleEndian.Uint16(id[18:20]))
		}
	}
	r.u32() // vers_option
	r.take(contextHandleLen)
	req.Max = r.u32()
	return req, r.ok
}

// ParseMap decodes an ept_map request stub, reading the interface from the
// first floor of the map tower.
func ParseMap(stub []byte) (Request, bool) {
	r := &ndrReader{b: stub, ok: true}
	var req Request
	if r.u32() != 0 {
		r.take(uuidLen) // object
	}
	if r.u32() != 0 {
		r.u32() // conformant max_count
		tower := r.take(int(r.u32()))
		req.Interface, req.InterfaceVersion = towerInterface(tower)
		r.align4()
	}
	r.take(contextHandleLen)
	req.Max = r.u32()
	return req, r.ok
}

// towerInterface returns the interface UUID and major.minor version from the
// first floor of a protocol tower (floor_count(2), then lhs_len(2) lhs
// rhs_len(2) rhs per floor; floor 1 lhs is 0x0d + uuid + vers_major, rhs is
// vers_minor).
func towerInterface(t []byte) (string, string) {
	if len(t) < 2+2+1+uuidLen+2+2+2 {
		return "", ""
	}
	lhsLen := int(binary.LittleEndian.Uint16(t[2:4]))
	if lhsLen != 1+uuidLen+2 || t[4] != 0x0d || len(t) < 4+lhsLen+4 {
		return "", ""
	}
	id := t[5 : 5+uuidLen]
	major := binary.LittleEndian.Uint16(t[5+uuidLen:])
	rhs := t[4+lhsLen:]
	minor := uint16(0)
	if binary.LittleEndian.Uint16(rhs[0:2]) == 2 {
		minor = binary.LittleEndian.Uint16(rhs[2:4])
	}
	return guidString(id), fmt.Sprintf("%d.%d", major, minor)
}

// BuildEmptyResult builds the [out] stub of ept_lookup and ept_map when no
// entry matches: a nil context handle, zero results, an empty conformant
// varying array sized max, and EPT_S_NOT_REGISTERED.
func BuildEmptyResult(max uint32) []byte {
	out := make([]byte, contextHandleLen+4+12+4)
	off := contextHandleLen
	binary.LittleEndian.PutUint32(out[off:], 0) // num_ents / num_towers
	off += 4
	binary.LittleEndian.PutUint32(out[off:], max) // max_count
	off += 4
	binary.LittleEndian.PutUint32(out[off:], 0) // offset
	off += 4
	binary.LittleEndian.PutUint32(out[off:], 0) // actual_count
	off += 4
	binary.LittleEndian.PutUint32(out[off:], StatusNotRegistered)
	return out
}

// guidString formats a 16-byte wire GUID (mixed-endian) as a canonical UUID.
func guidString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10:16])
}
