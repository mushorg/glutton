// Package enip parses and builds EtherNet/IP encapsulation messages (ODVA
// CIP Vol. 2, chapter 2) for the list and session commands a scanner sends
// before any CIP traffic.
//
// Every message starts with a 24-byte little-endian header: Command, Length
// (bytes after the header), SessionHandle, Status, an 8-byte SenderContext
// the receiver echoes unchanged, and Options. List replies carry a Common
// Packet Format item list (item count, then type/length/data per item).
package enip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// HeaderSize is the size of the encapsulation header.
const HeaderSize = 24

// Encapsulation commands.
const (
	CmdNOP               = 0x0000
	CmdListServices      = 0x0004
	CmdListIdentity      = 0x0063
	CmdListInterfaces    = 0x0064
	CmdRegisterSession   = 0x0065
	CmdUnRegisterSession = 0x0066
	CmdSendRRData        = 0x006F
	CmdSendUnitData      = 0x0070
)

// Encapsulation status codes.
const (
	StatusSuccess             = 0x0000
	StatusInvalidCommand      = 0x0001
	StatusInvalidSession      = 0x0064
	StatusInvalidLength       = 0x0065
	StatusUnsupportedRevision = 0x0069
)

// Common Packet Format item types.
const (
	itemIdentity = 0x000C
	itemServices = 0x0100
)

// ProtocolVersion is the only encapsulation protocol version defined.
const ProtocolVersion = 1

var ErrShort = errors.New("enip: short header")

// Header is the encapsulation header.
type Header struct {
	Command       uint16
	Length        uint16
	SessionHandle uint32
	Status        uint32
	SenderContext [8]byte
	Options       uint32
}

// ParseHeader decodes the first HeaderSize bytes of b.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShort
	}
	h := Header{
		Command:       binary.LittleEndian.Uint16(b[0:2]),
		Length:        binary.LittleEndian.Uint16(b[2:4]),
		SessionHandle: binary.LittleEndian.Uint32(b[4:8]),
		Status:        binary.LittleEndian.Uint32(b[8:12]),
		Options:       binary.LittleEndian.Uint32(b[20:24]),
	}
	copy(h.SenderContext[:], b[12:20])
	return h, nil
}

// Marshal encodes h followed by body, setting Length to len(body).
func (h Header) Marshal(body []byte) []byte {
	b := make([]byte, 0, HeaderSize+len(body))
	b = binary.LittleEndian.AppendUint16(b, h.Command)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(body)))
	b = binary.LittleEndian.AppendUint32(b, h.SessionHandle)
	b = binary.LittleEndian.AppendUint32(b, h.Status)
	b = append(b, h.SenderContext[:]...)
	b = binary.LittleEndian.AppendUint32(b, h.Options)
	return append(b, body...)
}

// CommandName returns the spec name of an encapsulation command.
func CommandName(cmd uint16) string {
	switch cmd {
	case CmdNOP:
		return "NOP"
	case CmdListServices:
		return "ListServices"
	case CmdListIdentity:
		return "ListIdentity"
	case CmdListInterfaces:
		return "ListInterfaces"
	case CmdRegisterSession:
		return "RegisterSession"
	case CmdUnRegisterSession:
		return "UnRegisterSession"
	case CmdSendRRData:
		return "SendRRData"
	case CmdSendUnitData:
		return "SendUnitData"
	}
	return fmt.Sprintf("0x%04x", cmd)
}

// StatusName names an encapsulation status for decoded write frames.
func StatusName(status uint32) string {
	switch status {
	case StatusSuccess:
		return "success"
	case StatusInvalidCommand:
		return "invalid_command"
	case StatusInvalidSession:
		return "invalid_session_handle"
	case StatusInvalidLength:
		return "invalid_length"
	case StatusUnsupportedRevision:
		return "unsupported_protocol_revision"
	}
	return fmt.Sprintf("0x%04x", status)
}

// Identity is the CIP Identity object as reported by ListIdentity.
type Identity struct {
	VendorID     uint16
	DeviceType   uint16
	ProductCode  uint16
	RevMajor     uint8
	RevMinor     uint8
	Status       uint16
	SerialNumber uint32
	ProductName  string
	State        uint8
}

// DefaultIdentity is a Rockwell Automation/Allen-Bradley ControlLogix
// EtherNet/IP bridge module (vendor 1, device type 12 "Communications
// Adapter"), a widely deployed module type on tcp/44818.
// Status 0x0030 and state 3 are what an operational module without I/O
// connections reports. SerialNumber is set per sensor by the caller.
var DefaultIdentity = Identity{
	VendorID:    1,
	DeviceType:  12,
	ProductCode: 166,
	RevMajor:    11,
	RevMinor:    2,
	Status:      0x0030,
	ProductName: "1756-EN2T/D",
	State:       3,
}

// identityItem encodes the CIP Identity CPF item data. The socket address
// fields are big-endian, as in a sockaddr_in.
func identityItem(id Identity, ip net.IP, port uint16) []byte {
	b := binary.LittleEndian.AppendUint16(nil, ProtocolVersion)
	b = binary.BigEndian.AppendUint16(b, 2) // AF_INET
	b = binary.BigEndian.AppendUint16(b, port)
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	b = append(b, ip4...)
	b = append(b, make([]byte, 8)...) // sin_zero
	b = binary.LittleEndian.AppendUint16(b, id.VendorID)
	b = binary.LittleEndian.AppendUint16(b, id.DeviceType)
	b = binary.LittleEndian.AppendUint16(b, id.ProductCode)
	b = append(b, id.RevMajor, id.RevMinor)
	b = binary.LittleEndian.AppendUint16(b, id.Status)
	b = binary.LittleEndian.AppendUint32(b, id.SerialNumber)
	name := id.ProductName
	if len(name) > 255 {
		name = name[:255]
	}
	b = append(b, byte(len(name)))
	b = append(b, name...)
	return append(b, id.State)
}

// cpf encodes a Common Packet Format list of one item, or none for typ 0.
func cpf(typ uint16, data []byte) []byte {
	if typ == 0 {
		return binary.LittleEndian.AppendUint16(nil, 0)
	}
	b := binary.LittleEndian.AppendUint16(nil, 1)
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// reply returns a header answering req with status, keeping the session
// handle, sender context and options.
func reply(req Header, status uint32) Header {
	return Header{
		Command:       req.Command,
		SessionHandle: req.SessionHandle,
		Status:        status,
		SenderContext: req.SenderContext,
		Options:       req.Options,
	}
}

// ListIdentityReply answers ListIdentity with one Identity item advertising
// ip:port as the device's socket address.
func ListIdentityReply(req Header, id Identity, ip net.IP, port uint16) []byte {
	return reply(req, StatusSuccess).Marshal(cpf(itemIdentity, identityItem(id, ip, port)))
}

// ListServicesReply answers ListServices with the "Communications" service,
// capable of CIP over TCP (bit 5) and class 0/1 UDP I/O (bit 8).
func ListServicesReply(req Header) []byte {
	data := binary.LittleEndian.AppendUint16(nil, ProtocolVersion)
	data = binary.LittleEndian.AppendUint16(data, 0x0120)
	name := make([]byte, 16)
	copy(name, "Communications")
	data = append(data, name...)
	return reply(req, StatusSuccess).Marshal(cpf(itemServices, data))
}

// ListInterfacesReply answers ListInterfaces with an empty item list.
func ListInterfacesReply(req Header) []byte {
	return reply(req, StatusSuccess).Marshal(cpf(0, nil))
}

// RegisterSessionReply answers RegisterSession. A valid request (4-byte body,
// protocol version 1, options 0) gets handle; otherwise the error status is
// returned with ok=false and no session is established.
func RegisterSessionReply(req Header, body []byte, handle uint32) (out []byte, ok bool) {
	if len(body) != 4 {
		return reply(req, StatusInvalidLength).Marshal(nil), false
	}
	if binary.LittleEndian.Uint16(body[0:2]) != ProtocolVersion || binary.LittleEndian.Uint16(body[2:4]) != 0 {
		r := reply(req, StatusUnsupportedRevision)
		return r.Marshal(binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, ProtocolVersion), 0)), false
	}
	r := reply(req, StatusSuccess)
	r.SessionHandle = handle
	return r.Marshal(body), true
}

// ErrorReply answers req with status and no data.
func ErrorReply(req Header, status uint32) []byte {
	return reply(req, status).Marshal(nil)
}
