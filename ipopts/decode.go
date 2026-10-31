package ipopts

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Option is one IPv4 header option as seen on the wire.
type Option struct {
	Type   uint8  `json:"type"`
	Name   string `json:"name,omitempty"`
	Length uint8  `json:"length,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// Frame is one captured packet with IP options for a producer event.
type Frame struct {
	Direction string   `json:"direction,omitempty"`
	Command   string   `json:"command,omitempty"`
	Options   []Option `json:"options,omitempty"`
	Malformed bool     `json:"malformed,omitempty"`
	Payload   []byte   `json:"payload,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Packet is a decoded IPv4 TCP packet that carried IP options.
type Packet struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Frame   Frame
}

// Decode finds the IPv4 header in data (Ethernet, VLAN, or Linux SLL) and
// hand-parses the header, options, and TCP ports/flags. Packets that are not
// IPv4+TCP or have IHL ≤ 5 return ok=false. Malformed options still yield a
// Packet with Frame.Malformed set.
func Decode(data []byte, linkType layers.LinkType) (pkt *Packet, ok bool) {
	if len(data) < 20 {
		return nil, false
	}
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	offset := ipv4Start(packet, data)
	if offset < 0 || offset >= len(data) {
		return nil, false
	}
	return decodeIPv4TCP(data[offset:])
}

func ipv4Start(packet gopacket.Packet, data []byte) int {
	offset := 0
	for _, layer := range packet.Layers() {
		lt := layer.LayerType()
		if lt == layers.LayerTypeIPv4 {
			return offset
		}
		if lt == gopacket.LayerTypeDecodeFailure {
			if looksLikeIPv4(data[offset:]) {
				return offset
			}
			return -1
		}
		offset += len(layer.LayerContents())
		if offset > len(data) {
			return -1
		}
	}
	// Fallback: scan remaining bytes for an IPv4 header (version 4).
	for i := 0; i+20 <= len(data); i++ {
		if looksLikeIPv4(data[i:]) {
			return i
		}
	}
	return -1
}

func looksLikeIPv4(b []byte) bool {
	return len(b) >= 20 && b[0]>>4 == 4
}

func decodeIPv4TCP(ip []byte) (*Packet, bool) {
	if len(ip) < 20 {
		return nil, false
	}
	vihl := ip[0]
	if vihl>>4 != 4 {
		return nil, false
	}
	ihl := int(vihl&0x0f) * 4
	if ihl < 20 {
		return nil, false
	}
	if ihl <= 20 {
		// No options; BPF should have filtered these.
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	proto := ip[9]
	if proto != 6 { // TCP
		return nil, false
	}

	malformed := false
	if totalLen < ihl {
		malformed = true
		totalLen = ihl
	}
	truncated := len(ip) < totalLen
	payloadEnd := len(ip)
	if !truncated && totalLen < payloadEnd {
		payloadEnd = totalLen
	}
	if ihl > len(ip) {
		malformed = true
		ihl = len(ip)
	}

	opts, optsMalformed := parseOptions(ip[20:ihl])
	malformed = malformed || optsMalformed

	srcIP := net.IP(append([]byte(nil), ip[12:16]...))
	dstIP := net.IP(append([]byte(nil), ip[16:20]...))

	var srcPort, dstPort uint16
	command := ""
	if ihl+13 <= len(ip) {
		tcp := ip[ihl:]
		srcPort = binary.BigEndian.Uint16(tcp[0:2])
		dstPort = binary.BigEndian.Uint16(tcp[2:4])
		flags := tcp[13]
		command = tcpFlagCommand(flags)
	} else {
		malformed = true
	}

	payload := append([]byte(nil), ip[:payloadEnd]...)
	return &Packet{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Frame: Frame{
			Command:   command,
			Options:   opts,
			Malformed: malformed,
			Payload:   payload,
			Truncated: truncated,
		},
	}, true
}

func parseOptions(opts []byte) ([]Option, bool) {
	var out []Option
	malformed := false
	i := 0
	for i < len(opts) {
		typ := opts[i]
		name := optionName(typ)
		switch typ {
		case 0: // EOL
			out = append(out, Option{Type: typ, Name: name, Length: 1})
			return out, malformed
		case 1: // NOP
			out = append(out, Option{Type: typ, Name: name, Length: 1})
			i++
			continue
		}
		if i+1 >= len(opts) {
			out = append(out, Option{Type: typ, Name: name})
			return out, true
		}
		length := opts[i+1]
		if length < 2 {
			out = append(out, Option{Type: typ, Name: name, Length: length})
			return out, true
		}
		end := i + int(length)
		if end > len(opts) {
			out = append(out, Option{
				Type:   typ,
				Name:   name,
				Length: length,
				Data:   append([]byte(nil), opts[i+2:]...),
			})
			return out, true
		}
		out = append(out, Option{
			Type:   typ,
			Name:   name,
			Length: length,
			Data:   append([]byte(nil), opts[i+2:end]...),
		})
		i = end
	}
	return out, malformed
}

func optionName(typ uint8) string {
	if name, ok := ipv4OptionNames[typ]; ok {
		return name
	}
	return fmt.Sprintf("%d", typ)
}

// IANA IPv4 Option Numbers (common names used in analysis).
var ipv4OptionNames = map[uint8]string{
	0:   "EOL",
	1:   "NOP",
	7:   "RR",
	68:  "TS",
	130: "SEC",
	131: "LSRR",
	133: "CIPSO",
	136: "SATID",
	137: "SSRR",
	148: "RTRALT",
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

func tcpFlagCommand(flags uint8) string {
	masked := flags & (tcpFIN | tcpSYN | tcpRST | tcpPSH | tcpACK)
	switch masked {
	case tcpSYN:
		return "SYN"
	case tcpSYN | tcpACK:
		return "SYN-ACK"
	case tcpACK:
		return "ACK"
	case tcpRST, tcpRST | tcpACK:
		return "RST"
	case tcpFIN:
		return "FIN"
	case tcpFIN | tcpACK:
		return "FIN-ACK"
	case tcpPSH | tcpACK:
		return "PSH-ACK"
	default:
		return fmt.Sprintf("flags=0x%02x", flags)
	}
}
