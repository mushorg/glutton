// Package nbns parses NetBIOS name service queries and builds the replies
// a Windows file server sends (RFC 1002 §4.2.13 and §4.2.18).
package nbns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/helpers/netbios"
)

const (
	headerLen = 12

	opQuery        = 0
	opRegistration = 5
	opRelease      = 6

	qtypeNB     uint16 = 0x0020
	qtypeNBSTAT uint16 = 0x0021

	flagResponse      uint16 = 0x8000
	flagAuthoritative uint16 = 0x0400
	flagBroadcast     uint16 = 0x0010

	nameActive uint16 = 0x0400
	nameGroup  uint16 = 0x8000
)

var (
	ErrTruncated = errors.New("truncated NBNS message")
	ErrMalformed = errors.New("malformed NBNS message")
)

// NodeName is one name in a node-status table.
type NodeName struct {
	Name   string
	Suffix byte
	Group  bool
}

// Message is a parsed NBNS query. Fields after the header are set only when
// the first question decoded.
type Message struct {
	TXID        uint16
	Flags       uint16
	Questions   int
	Name        string
	Suffix      byte
	NameOK      bool
	Qtype       uint16
	EncodedName []byte // question name, echoed in a reply
}

// Response reports the QR bit.
func (m Message) Response() bool { return m.Flags&flagResponse != 0 }

// Broadcast reports the NBNS broadcast flag. Scanners set it on unicast
// NBSTAT queries; the handler still answers those, and refuses only when
// the destination address itself is broadcast or multicast.
func (m Message) Broadcast() bool { return m.Flags&flagBroadcast != 0 }

// Opcode is the 4-bit operation code.
func (m Message) Opcode() int { return int((m.Flags >> 11) & 0xf) }

// Command is the leaf operation: NBSTAT, NB, REGISTRATION, RELEASE or UNKNOWN.
func (m Message) Command() string {
	switch m.Opcode() {
	case opRegistration:
		return "REGISTRATION"
	case opRelease:
		return "RELEASE"
	case opQuery:
		if !m.NameOK {
			return "UNKNOWN"
		}
		switch m.Qtype {
		case qtypeNBSTAT:
			return "NBSTAT"
		case qtypeNB:
			return "NB"
		}
	}
	return "UNKNOWN"
}

// Path is the decoded name and suffix, e.g. "*<00>" or "SERVER<20>".
func (m Message) Path() string {
	if !m.NameOK {
		return ""
	}
	return fmt.Sprintf("%s<%02X>", m.Name, m.Suffix)
}

// Parse decodes the header and the first question. A short header returns
// ErrTruncated with a zero Message; a bad name returns ErrMalformed with the
// header fields filled.
func Parse(data []byte) (Message, error) {
	var m Message
	if len(data) < headerLen {
		return m, ErrTruncated
	}
	m.TXID = binary.BigEndian.Uint16(data[0:2])
	m.Flags = binary.BigEndian.Uint16(data[2:4])
	m.Questions = int(binary.BigEndian.Uint16(data[4:6]))
	if m.Questions == 0 {
		return m, nil
	}
	name, suffix, n, ok := netbios.Decode(data[headerLen:])
	if !ok {
		return m, ErrMalformed
	}
	if len(data) < headerLen+n+4 {
		return m, ErrTruncated
	}
	m.Name = name
	m.Suffix = suffix
	m.NameOK = true
	m.EncodedName = append([]byte(nil), data[headerLen:headerLen+n]...)
	m.Qtype = binary.BigEndian.Uint16(data[headerLen+n : headerLen+n+2])
	return m, nil
}

// BuildNodeStatus builds an NBSTAT response echoing qname (the encoded
// question) and listing names. The statistics block carries mac and zeros.
func BuildNodeStatus(txid uint16, qname []byte, names []NodeName, mac [6]byte) []byte {
	rdata := nodeStatusData(names, mac)
	out := header(txid, qname, qtypeNBSTAT)
	out = append(out, 0xC0, 0x0C) // pointer at the question name
	out = binary.BigEndian.AppendUint16(out, qtypeNBSTAT)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

// BuildNameQuery builds a positive NB response for qname with ip.
func BuildNameQuery(txid uint16, qname []byte, ip net.IP) []byte {
	ip = ip.To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	out := header(txid, qname, qtypeNB)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, qtypeNB)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint16(out, 6)
	out = binary.BigEndian.AppendUint16(out, 0) // unique
	return append(out, ip...)
}

func header(txid uint16, qname []byte, qtype uint16) []byte {
	out := make([]byte, 0, headerLen+len(qname)+4)
	out = binary.BigEndian.AppendUint16(out, txid)
	out = binary.BigEndian.AppendUint16(out, flagResponse|flagAuthoritative)
	out = binary.BigEndian.AppendUint16(out, 1) // question echoed
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = append(out, qname...)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, 1)
	return out
}

func nodeStatusData(names []NodeName, mac [6]byte) []byte {
	r := []byte{byte(len(names))}
	for _, n := range names {
		raw := make([]byte, 16)
		for i := range raw[:15] {
			raw[i] = ' '
		}
		copy(raw[:15], n.Name)
		raw[15] = n.Suffix
		r = append(r, raw...)
		flags := nameActive
		if n.Group {
			flags |= nameGroup
		}
		r = binary.BigEndian.AppendUint16(r, flags)
	}
	r = append(r, mac[:]...)
	// UNIT_ID is the first 6 of the 46-byte statistics block (RFC 1002 §4.2.18).
	return append(r, make([]byte, 40)...)
}
