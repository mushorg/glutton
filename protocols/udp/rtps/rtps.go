// Package rtps parses RTPS (Real-Time Publish-Subscribe, the DDS wire
// protocol) datagrams: the 20-byte header, the submessage list, and for the
// first DATA submessage the discovery parameter list (SPDP participant
// announcements). It is parse-only; nothing here builds a reply.
package rtps

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// HeaderLen is magic(4) + version(2) + vendor(2) + guidPrefix(12).
	HeaderLen = 20

	maxSubmessages  = 32
	maxParams       = 64
	maxLocators     = 8
	maxVendorString = 4
	maxStringLen    = 256
	minVendorString = 6
)

var (
	ErrNotRTPS   = errors.New("not an RTPS datagram")
	ErrTruncated = errors.New("truncated RTPS message")
)

// Submessage IDs.
const (
	idPad           = 0x01
	idAckNack       = 0x06
	idHeartbeat     = 0x07
	idGap           = 0x08
	idInfoTS        = 0x09
	idInfoSrc       = 0x0c
	idInfoReplyIP4  = 0x0d
	idInfoDst       = 0x0e
	idInfoReply     = 0x0f
	idNackFrag      = 0x12
	idHeartbeatFrag = 0x13
	idData          = 0x15
	idDataFrag      = 0x16
)

var submessageNames = map[uint8]string{
	idPad:           "PAD",
	idAckNack:       "ACKNACK",
	idHeartbeat:     "HEARTBEAT",
	idGap:           "GAP",
	idInfoTS:        "INFO_TS",
	idInfoSrc:       "INFO_SRC",
	idInfoReplyIP4:  "INFO_REPLY_IP4",
	idInfoDst:       "INFO_DST",
	idInfoReply:     "INFO_REPLY",
	idNackFrag:      "NACK_FRAG",
	idHeartbeatFrag: "HEARTBEAT_FRAG",
	idData:          "DATA",
	idDataFrag:      "DATA_FRAG",
}

// Submessage flag bits (shared by all submessages, or specific to DATA).
const (
	flagEndianLittle  = 0x01
	flagDataInlineQos = 0x02
	flagDataPayload   = 0x04
)

// Parameter IDs of the SPDP participant announcement.
const (
	pidSentinel        = 0x0001
	pidDefaultUnicast  = 0x0031
	pidMetaUnicast     = 0x0032
	pidMetaMulticast   = 0x0033
	pidDefaultMulti    = 0x0048
	pidUserData        = 0x002c
	pidDomainID        = 0x000f
	pidEntityName      = 0x0062
	pidParticipantGUID = 0x0050
	pidVendorSpecific  = 0x8000 // bit 15 set marks a vendor-specific PID
)

// Encapsulation identifiers of a serialized parameter list.
const (
	encPLCDRBE = 0x0002
	encPLCDRLE = 0x0003
)

var vendorNames = map[uint16]string{
	0x0101: "RTI Connext DDS",
	0x0102: "ADLINK OpenSplice",
	0x0103: "OpenDDS",
	0x0106: "TwinOaks CoreDX",
	0x010f: "eProsima Fast DDS",
	0x0110: "Eclipse Cyclone DDS",
	0x0111: "GurumDDS",
}

// Submessage is one entry of the submessage list.
type Submessage struct {
	Kind   string `json:"kind"`
	Flags  uint8  `json:"flags"`
	Length int    `json:"length"`
}

// Packet is the parsed view of one RTPS datagram.
type Packet struct {
	Version     string
	VendorID    string // hex, e.g. "0101"
	Vendor      string // name when the vendor ID is known
	GUIDPrefix  string // hex
	Submessages []Submessage
	// Command is the leaf operation: DATA(p) for an SPDP participant
	// announcement, DATA(w)/DATA(r) for SEDP, else the first submessage kind.
	Command        string
	WriterEntityID string // hex, from the first DATA submessage
	WriterSN       uint64

	ParticipantGUID string // hex, PID_PARTICIPANT_GUID
	UserData        string
	EntityName      string
	DomainID        *uint32
	Locators        []string
	// VendorStrings are printable runs from vendor-specific parameters
	// ("0x8007=name"). Heuristic: the layout is vendor defined.
	VendorStrings []string
}

// LooksLikeRTPS reports whether data starts with an RTPS 2.x header.
func LooksLikeRTPS(data []byte) bool {
	return len(data) >= HeaderLen && bytes.Equal(data[:4], []byte("RTPS")) && data[4] == 2
}

func byteOrder(flags uint8) binary.ByteOrder {
	if flags&flagEndianLittle != 0 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// Parse decodes data. On ErrTruncated the returned Packet holds everything
// parsed before the cut.
func Parse(data []byte) (Packet, error) {
	if !LooksLikeRTPS(data) {
		if len(data) >= 4 && bytes.Equal(data[:4], []byte("RTPS")) {
			return Packet{}, ErrTruncated
		}
		return Packet{}, ErrNotRTPS
	}
	vendor := binary.BigEndian.Uint16(data[6:8])
	pkt := Packet{
		Version:    fmt.Sprintf("%d.%d", data[4], data[5]),
		VendorID:   fmt.Sprintf("%04x", vendor),
		Vendor:     vendorNames[vendor],
		GUIDPrefix: hex.EncodeToString(data[8:HeaderLen]),
	}

	rest := data[HeaderLen:]
	dataSeen := false
	for len(rest) > 0 && len(pkt.Submessages) < maxSubmessages {
		if len(rest) < 4 {
			return finish(pkt), ErrTruncated
		}
		id, flags := rest[0], rest[1]
		length := int(byteOrder(flags).Uint16(rest[2:4]))
		body := rest[4:]
		if length == 0 && id != idPad && id != idInfoTS {
			length = len(body) // last submessage runs to the end of the message
		}
		kind, ok := submessageNames[id]
		if !ok {
			kind = fmt.Sprintf("0x%02x", id)
		}
		if length > len(body) {
			pkt.Submessages = append(pkt.Submessages, Submessage{Kind: kind, Flags: flags, Length: length})
			return finish(pkt), ErrTruncated
		}
		pkt.Submessages = append(pkt.Submessages, Submessage{Kind: kind, Flags: flags, Length: length})
		if id == idData && !dataSeen {
			dataSeen = true
			parseData(body[:length], flags, &pkt)
		}
		rest = body[length:]
	}
	return finish(pkt), nil
}

func finish(pkt Packet) Packet {
	pkt.Command = "UNKNOWN"
	for _, s := range pkt.Submessages {
		switch s.Kind {
		case "PAD", "INFO_TS", "INFO_SRC", "INFO_DST", "INFO_REPLY", "INFO_REPLY_IP4":
			continue
		}
		pkt.Command = s.Kind
		break
	}
	if pkt.Command == "UNKNOWN" && len(pkt.Submessages) > 0 {
		pkt.Command = pkt.Submessages[0].Kind
	}
	if pkt.Command == "DATA" {
		switch pkt.WriterEntityID {
		case "000100c2":
			pkt.Command = "DATA(p)"
		case "000003c2":
			pkt.Command = "DATA(w)"
		case "000004c2":
			pkt.Command = "DATA(r)"
		}
	}
	return pkt
}

// walkParams iterates a ParameterList, returning the offset after the
// sentinel and whether the sentinel was found.
func walkParams(b []byte, order binary.ByteOrder, fn func(pid uint16, val []byte)) (int, bool) {
	off := 0
	for n := 0; n < maxParams; n++ {
		if off+4 > len(b) {
			return off, false
		}
		pid := order.Uint16(b[off:])
		l := int(order.Uint16(b[off+2:]))
		off += 4
		if pid == pidSentinel {
			return off, true
		}
		if off+l > len(b) {
			return len(b), false
		}
		if fn != nil {
			fn(pid, b[off:off+l])
		}
		off += l
	}
	return off, false
}

func parseData(body []byte, flags uint8, pkt *Packet) {
	if len(body) < 20 {
		return
	}
	order := byteOrder(flags)
	pkt.WriterEntityID = hex.EncodeToString(body[8:12])
	pkt.WriterSN = uint64(order.Uint32(body[12:16]))<<32 | uint64(order.Uint32(body[16:20]))

	off := 4 + int(order.Uint16(body[2:4]))
	if off > len(body) {
		return
	}
	if flags&flagDataInlineQos != 0 {
		end, ok := walkParams(body[off:], order, nil)
		if !ok {
			return
		}
		off += end
	}
	if flags&flagDataPayload == 0 || off+4 > len(body) {
		return
	}
	var plOrder binary.ByteOrder
	switch binary.BigEndian.Uint16(body[off:]) {
	case encPLCDRLE:
		plOrder = binary.LittleEndian
	case encPLCDRBE:
		plOrder = binary.BigEndian
	default:
		return
	}
	walkParams(body[off+4:], plOrder, func(pid uint16, val []byte) {
		pkt.applyParam(pid, val, plOrder)
	})
}

func (p *Packet) applyParam(pid uint16, val []byte, order binary.ByteOrder) {
	switch pid {
	case pidParticipantGUID:
		if len(val) == 16 {
			p.ParticipantGUID = hex.EncodeToString(val)
		}
	case pidUserData:
		p.UserData = cdrString(val, order)
	case pidEntityName:
		p.EntityName = cdrString(val, order)
	case pidDomainID:
		if len(val) >= 4 {
			d := order.Uint32(val)
			p.DomainID = &d
		}
	case pidDefaultUnicast, pidMetaUnicast, pidMetaMulticast, pidDefaultMulti:
		if len(val) == 24 && len(p.Locators) < maxLocators {
			p.Locators = append(p.Locators, locator(val, order))
		}
	default:
		if pid&pidVendorSpecific != 0 && len(p.VendorStrings) < maxVendorString {
			if s := printableRun(val); s != "" {
				p.VendorStrings = append(p.VendorStrings, fmt.Sprintf("0x%04x=%s", pid, s))
			}
		}
	}
}

// cdrString decodes a uint32 length followed by that many bytes (a CDR string
// or octet sequence), dropping trailing NULs.
func cdrString(val []byte, order binary.ByteOrder) string {
	if len(val) < 4 {
		return ""
	}
	n := int(order.Uint32(val))
	if n < 0 || n > len(val)-4 {
		return ""
	}
	s := strings.TrimRight(string(val[4:4+n]), "\x00")
	if len(s) > maxStringLen {
		s = s[:maxStringLen]
	}
	return s
}

// locator renders kind(4) port(4) address(16) as "udp4:host:port" or
// "udp6:host:port". Other kinds are shown as "kind<N>:port".
func locator(val []byte, order binary.ByteOrder) string {
	kind := order.Uint32(val[0:4])
	port := order.Uint32(val[4:8])
	addr := val[8:24]
	switch kind {
	case 1:
		return fmt.Sprintf("udp4:%d.%d.%d.%d:%d", addr[12], addr[13], addr[14], addr[15], port)
	case 2:
		return fmt.Sprintf("udp6:%x:%d", addr, port)
	}
	return fmt.Sprintf("kind%d:%d", kind, port)
}

// printableRun returns the longest run of printable ASCII in b if it is at
// least minVendorString bytes long.
func printableRun(b []byte) string {
	var best, cur []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
			continue
		}
		if len(cur) > len(best) {
			best = cur
		}
		cur = nil
	}
	if len(cur) > len(best) {
		best = cur
	}
	if len(best) < minVendorString {
		return ""
	}
	if len(best) > maxStringLen {
		best = best[:maxStringLen]
	}
	return string(best)
}
