package smb

import (
	"encoding/binary"
	"unicode/utf16"
)

// MS-SRVS (srvsvc) share enumeration. Only NetrShareEnum is answered, from a
// fixed, fake share table; every other operation still faults, so no real
// server state is exposed.

const (
	// SrvsvcUUID is the srvsvc interface id as formatted by BindContext.InterfaceUUID.
	SrvsvcUUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
	// SrvsvcOpNetrShareEnum is NetrShareEnum (opnum 15).
	SrvsvcOpNetrShareEnum = 15

	dcerpcPTypeResponse = 0x02

	shareTypeDisk      = 0x00000000
	shareTypeIPC       = 0x80000003
	shareTypeDiskAdmin = 0x80000000
)

// Share is one entry of the advertised share table.
type Share struct {
	Name   string
	Type   uint32
	Remark string
}

// Shares is the share table returned by NetrShareEnum. It mirrors a default
// Windows host plus the two data shares HoneySMB advertises.
var Shares = []Share{
	{"ADMIN$", shareTypeDiskAdmin, "Remote Admin"},
	{"C$", shareTypeDiskAdmin, "Default share"},
	{"DEMO", shareTypeDisk, "DEMO"},
	{"IPC$", shareTypeIPC, "Remote IPC"},
	{"TMP", shareTypeDisk, "TMP"},
}

// ParseNetShareEnumLevel returns the info level requested by a NetrShareEnum
// stub (ServerName unique pointer, then InfoStruct.Level).
func ParseNetShareEnumLevel(stub []byte) (uint32, bool) {
	if len(stub) < 4 {
		return 0, false
	}
	off := 4
	if binary.LittleEndian.Uint32(stub[0:4]) != 0 {
		// conformant varying string: max, offset, actual, then actual WCHARs.
		if len(stub) < off+12 {
			return 0, false
		}
		actual := int(binary.LittleEndian.Uint32(stub[off+8 : off+12]))
		if actual < 0 || actual > len(stub) {
			return 0, false
		}
		off += 12 + actual*2
		off = (off + 3) &^ 3
	}
	if len(stub) < off+4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(stub[off : off+4]), true
}

// BuildNetShareEnumResponse builds the response PDU for a NetrShareEnum call at
// level 0 or 1. ok is false for other levels (the caller should fault).
func BuildNetShareEnumResponse(callID uint32, ctxID uint16, level uint32, shares []Share) ([]byte, bool) {
	if level != 0 && level != 1 {
		return nil, false
	}
	var stub []byte
	u32 := func(v uint32) { stub = binary.LittleEndian.AppendUint32(stub, v) }
	str := func(s string) {
		w := utf16.Encode([]rune(s))
		w = append(w, 0)
		u32(uint32(len(w))) // max count
		u32(0)              // offset
		u32(uint32(len(w))) // actual count
		for _, c := range w {
			stub = binary.LittleEndian.AppendUint16(stub, c)
		}
		for len(stub)%4 != 0 {
			stub = append(stub, 0)
		}
	}

	ref := uint32(0x00020000)
	next := func() uint32 { r := ref; ref += 4; return r }

	u32(level)               // InfoStruct.Level
	u32(level)               // union switch
	u32(next())              // container pointer
	u32(uint32(len(shares))) // EntriesRead
	u32(next())              // array pointer
	u32(uint32(len(shares))) // array max count
	for _, s := range shares {
		u32(next()) // netname
		if level == 1 {
			u32(s.Type)
			u32(next()) // remark
		}
	}
	for _, s := range shares {
		str(s.Name)
		if level == 1 {
			str(s.Remark)
		}
	}
	u32(uint32(len(shares))) // TotalEntries
	u32(0)                   // ResumeHandle (null pointer)
	u32(0)                   // WERR_OK

	// alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1), then stub.
	body := make([]byte, 8, 8+len(stub))
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(body[4:6], ctxID)
	body = append(body, stub...)
	return dcerpcFrame(dcerpcPTypeResponse, callID, body), true
}
