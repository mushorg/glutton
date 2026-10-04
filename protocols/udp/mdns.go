package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxMDNSPayload = 1024
	dnsHeaderLen   = 12
	maxDNSLabels   = 128
)

// Common DNS QTYPEs seen on mDNS / DNS-SD.
var dnsQTypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	255: "ANY",
}

type dnsQuestion struct {
	QName     string `json:"qname,omitempty"`
	QType     uint16 `json:"qtype,omitempty"`
	QTypeName string `json:"qtype_name,omitempty"`
	QClass    uint16 `json:"qclass,omitempty"`
}

type parsedMDNS struct {
	Direction string        `json:"direction,omitempty"`
	Command   string        `json:"command,omitempty"`
	Path      string        `json:"path,omitempty"`
	Questions []dnsQuestion `json:"questions,omitempty"`
	Payload   []byte        `json:"payload,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

func dnsQTypeName(qtype uint16) string {
	if name, ok := dnsQTypeNames[qtype]; ok {
		return name
	}
	return "UNKNOWN"
}

// readDNSName decodes a DNS wire name starting at off. Compression pointers are
// followed with a visit limit so truncated or cyclic packets cannot loop forever.
func readDNSName(msg []byte, off int) (name string, next int, err error) {
	if off < 0 || off >= len(msg) {
		return "", off, fmt.Errorf("name offset out of range")
	}

	var labels []string
	jumped := false
	pos := off
	for i := 0; i < maxDNSLabels; i++ {
		if pos >= len(msg) {
			return "", off, fmt.Errorf("truncated DNS name")
		}
		l := int(msg[pos])
		if l == 0 {
			if !jumped {
				next = pos + 1
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			return strings.Join(labels, "."), next, nil
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", off, fmt.Errorf("truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3fff)
			if !jumped {
				next = pos + 2
				jumped = true
			}
			pos = ptr
			continue
		}
		if l&0xc0 != 0 {
			return "", off, fmt.Errorf("unsupported name label type")
		}
		pos++
		if pos+l > len(msg) {
			return "", off, fmt.Errorf("truncated DNS label")
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
		if !jumped {
			next = pos
		}
	}
	return "", off, fmt.Errorf("too many DNS labels")
}

func parseMDNSQuestions(data []byte) ([]dnsQuestion, error) {
	if len(data) < dnsHeaderLen {
		return nil, fmt.Errorf("shorter than DNS header")
	}
	qdcount := binary.BigEndian.Uint16(data[4:6])
	off := dnsHeaderLen
	questions := make([]dnsQuestion, 0, qdcount)
	for i := 0; i < int(qdcount); i++ {
		qname, next, err := readDNSName(data, off)
		if err != nil {
			return questions, err
		}
		if next+4 > len(data) {
			return questions, fmt.Errorf("truncated question type/class")
		}
		qtype := binary.BigEndian.Uint16(data[next : next+2])
		qclass := binary.BigEndian.Uint16(data[next+2 : next+4])
		questions = append(questions, dnsQuestion{
			QName:     qname,
			QType:     qtype,
			QTypeName: dnsQTypeName(qtype),
			QClass:    qclass & 0x7fff, // clear mDNS cache-flush / unicast-response bit
		})
		off = next + 4
	}
	return questions, nil
}

// HandleMDNS parses an mDNS / DNS-SD UDP datagram and emits one producer event
// with question qname/qtype tagged in decoded. It does not reply.
func HandleMDNS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxMDNSPayload))
	copy(payload, data[:len(payload)])

	events := []parsedMDNS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("mdns", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedMDNS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mdns"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame := parsedMDNS{Direction: "read", Payload: payload, Truncated: len(data) > maxMDNSPayload}
	questions, err := parseMDNSQuestions(payload)
	frame.Questions = questions
	if len(questions) > 0 {
		frame.Command = questions[0].QTypeName
		frame.Path = questions[0].QName
	}
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse mDNS questions",
			slog.String("protocol", "mdns"),
			producer.ErrAttr(err),
			slog.Int("bytes", len(payload)),
			slog.Int("questions", len(questions)),
		)
	}

	qnames := make([]string, 0, len(questions))
	for _, q := range questions {
		qnames = append(qnames, fmt.Sprintf("%s/%s", q.QName, q.QTypeName))
	}
	logger.Info("mDNS UDP packet received",
		slog.String("handler", "mdns"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.Int("questions", len(questions)),
		slog.String("qnames", strings.Join(qnames, ",")),
	)
	return nil
}
