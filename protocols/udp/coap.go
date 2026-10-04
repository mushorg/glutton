package udp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxCoAPPayload = 1024

	coapTypeCON = 0
	coapTypeNON = 1
	coapTypeACK = 2
	coapTypeRST = 3

	coapCodeGET     = 1
	coapCodePOST    = 2
	coapCodePUT     = 3
	coapCodeDELETE  = 4
	coapCodeCreated = 65 // 2.01
	coapCodeDeleted = 66 // 2.02
	coapCodeContent = 69 // 2.05

	coapOptObserve        = 6
	coapOptURIPath        = 11
	coapOptContentFormat  = 12
	coapContentFormatText = 0
	coapContentFormatLink = 40

	coapWellKnownCore = ".well-known/core"
	coapLinkBody      = "</ps/temp>,</ps/hum>"
	coapGETBody       = "21.5"
)

var (
	errCoAPTruncated = errors.New("truncated CoAP message")
	errCoAPInvalid   = errors.New("invalid CoAP message")
)

var coapTypeNames = map[uint8]string{
	coapTypeCON: "CON",
	coapTypeNON: "NON",
	coapTypeACK: "ACK",
	coapTypeRST: "RST",
}

var coapCodeNames = map[uint8]string{
	coapCodeGET:     "GET",
	coapCodePOST:    "POST",
	coapCodePUT:     "PUT",
	coapCodeDELETE:  "DELETE",
	coapCodeCreated: "CREATED",
	coapCodeDeleted: "DELETED",
	coapCodeContent: "CONTENT",
}

type parsedCoAP struct {
	Direction string  `json:"direction,omitempty"`
	Command   string  `json:"command,omitempty"`
	Status    string  `json:"status,omitempty"`
	Type      string  `json:"type,omitempty"`
	Code      uint8   `json:"code,omitempty"`
	CodeName  string  `json:"code_name,omitempty"`
	MessageID uint16  `json:"message_id,omitempty"`
	Token     string  `json:"token,omitempty"`
	Path      string  `json:"path,omitempty"`
	Observe   *uint32 `json:"observe,omitempty"`
	Payload   []byte  `json:"payload,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
}

type coapMessage struct {
	Type      uint8
	Code      uint8
	MessageID uint16
	Token     []byte
	Path      string
	Observe   *uint32
	Body      []byte
}

func coapTypeName(t uint8) string {
	if name, ok := coapTypeNames[t]; ok {
		return name
	}
	return "UNKNOWN"
}

func coapCodeName(code uint8) string {
	if name, ok := coapCodeNames[code]; ok {
		return name
	}
	return "UNKNOWN"
}

func looksLikeCoAP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	ver := data[0] >> 6
	tkl := data[0] & 0x0f
	code := data[1]
	return ver == 1 && tkl <= 8 && code >= coapCodeGET && code <= coapCodeDELETE
}

func parseCoAP(data []byte) (parsedCoAP, coapMessage, error) {
	frame := parsedCoAP{Direction: "read", Payload: data, CodeName: "UNKNOWN", Command: "UNKNOWN"}
	if len(data) < 4 {
		return frame, coapMessage{}, errCoAPTruncated
	}

	ver := data[0] >> 6
	typ := (data[0] >> 4) & 0x03
	tkl := int(data[0] & 0x0f)
	if ver != 1 || tkl > 8 {
		return frame, coapMessage{}, errCoAPInvalid
	}
	if 4+tkl > len(data) {
		return frame, coapMessage{}, errCoAPTruncated
	}

	msg := coapMessage{
		Type:      typ,
		Code:      data[1],
		MessageID: binary.BigEndian.Uint16(data[2:4]),
		Token:     append([]byte(nil), data[4:4+tkl]...),
	}
	frame.Type = coapTypeName(typ)
	frame.Code = msg.Code
	frame.CodeName = coapCodeName(msg.Code)
	frame.Command = frame.CodeName
	frame.MessageID = msg.MessageID
	if tkl > 0 {
		frame.Token = hex.EncodeToString(msg.Token)
	}

	rest := data[4+tkl:]
	var (
		optNum uint32
		paths  []string
		err    error
	)
	for len(rest) > 0 {
		if rest[0] == 0xff {
			msg.Body = append([]byte(nil), rest[1:]...)
			break
		}
		delta := uint32(rest[0] >> 4)
		optLen := uint32(rest[0] & 0x0f)
		rest = rest[1:]
		if delta == 15 || optLen == 15 {
			return frame, msg, errCoAPInvalid
		}
		delta, rest, err = coapExt(delta, rest)
		if err != nil {
			return frame, msg, err
		}
		optLen, rest, err = coapExt(optLen, rest)
		if err != nil {
			return frame, msg, err
		}
		if uint32(len(rest)) < optLen {
			return frame, msg, errCoAPTruncated
		}
		value := rest[:optLen]
		rest = rest[optLen:]
		optNum += delta
		switch optNum {
		case coapOptURIPath:
			paths = append(paths, string(value))
		case coapOptObserve:
			obs := coapUint(value)
			msg.Observe = &obs
			frame.Observe = &obs
		}
	}
	msg.Path = strings.Join(paths, "/")
	frame.Path = msg.Path
	return frame, msg, nil
}

func coapExt(nibble uint32, rest []byte) (uint32, []byte, error) {
	switch nibble {
	case 13:
		if len(rest) < 1 {
			return 0, rest, errCoAPTruncated
		}
		return uint32(rest[0]) + 13, rest[1:], nil
	case 14:
		if len(rest) < 2 {
			return 0, rest, errCoAPTruncated
		}
		return uint32(binary.BigEndian.Uint16(rest[:2])) + 269, rest[2:], nil
	default:
		return nibble, rest, nil
	}
}

func coapUint(value []byte) uint32 {
	var n uint32
	for _, b := range value {
		n = (n << 8) | uint32(b)
	}
	return n
}

type coapOption struct {
	num   uint32
	value []byte
}

func encodeCoAP(typ, code uint8, messageID uint16, token []byte, opts []coapOption, body []byte) []byte {
	if len(token) > 8 {
		token = token[:8]
	}
	header := make([]byte, 4)
	header[0] = (1 << 6) | ((typ & 0x03) << 4) | byte(len(token)&0x0f)
	header[1] = code
	binary.BigEndian.PutUint16(header[2:4], messageID)
	out := append(header, token...)

	var prev uint32
	for _, opt := range opts {
		delta := opt.num - prev
		prev = opt.num
		deltaNib, deltaExt := coapExtEncode(delta)
		lenNib, lenExt := coapExtEncode(uint32(len(opt.value)))
		out = append(out, byte(deltaNib<<4)|byte(lenNib))
		out = append(out, deltaExt...)
		out = append(out, lenExt...)
		out = append(out, opt.value...)
	}
	if body != nil {
		out = append(out, 0xff)
		out = append(out, body...)
	}
	return out
}

func coapExtEncode(n uint32) (uint8, []byte) {
	switch {
	case n < 13:
		return uint8(n), nil
	case n < 269:
		return 13, []byte{byte(n - 13)}
	default:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(n-269))
		return 14, b
	}
}

func encodeContentFormat(fmtID uint16) []byte {
	if fmtID < 256 {
		return []byte{byte(fmtID)}
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, fmtID)
	return b
}

func encodeObserve(n uint32) []byte {
	if n == 0 {
		return []byte{0}
	}
	if n < 256 {
		return []byte{byte(n)}
	}
	if n < 65536 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(n))
		return b
	}
	b := make([]byte, 3)
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
	return b
}

func replyType(reqType uint8) uint8 {
	if reqType == coapTypeCON {
		return coapTypeACK
	}
	return coapTypeNON
}

func buildCoAPReply(msg coapMessage) ([]byte, parsedCoAP, bool) {
	if msg.Type == coapTypeACK || msg.Type == coapTypeRST {
		return nil, parsedCoAP{}, false
	}
	respType := replyType(msg.Type)
	var (
		code uint8
		body []byte
		opts []coapOption
	)
	switch msg.Code {
	case 0:
		if msg.Type != coapTypeCON {
			return nil, parsedCoAP{}, false
		}
		code = 0
	case coapCodeGET:
		code = coapCodeContent
		if msg.Path == coapWellKnownCore {
			body = []byte(coapLinkBody)
			opts = append(opts, coapOption{num: coapOptContentFormat, value: encodeContentFormat(coapContentFormatLink)})
		} else {
			body = []byte(coapGETBody)
			opts = append(opts, coapOption{num: coapOptContentFormat, value: encodeContentFormat(coapContentFormatText)})
		}
		if msg.Observe != nil {
			opts = append([]coapOption{{num: coapOptObserve, value: encodeObserve(1)}}, opts...)
		}
	case coapCodePOST, coapCodePUT:
		code = coapCodeCreated
	case coapCodeDELETE:
		code = coapCodeDeleted
	default:
		return nil, parsedCoAP{}, false
	}

	resp := encodeCoAP(respType, code, msg.MessageID, msg.Token, opts, body)
	frame := parsedCoAP{
		Direction: "write",
		Command:   coapCodeName(code),
		Status:    coapCodeName(code),
		Type:      coapTypeName(respType),
		Code:      code,
		CodeName:  coapCodeName(code),
		MessageID: msg.MessageID,
		Path:      msg.Path,
		Payload:   resp,
	}
	if len(msg.Token) > 0 {
		frame.Token = hex.EncodeToString(msg.Token)
	}
	return resp, frame, true
}

// HandleCoAP parses a CoAP datagram, answers GET/POST/PUT/DELETE (and empty CON pings),
// and emits one producer event with per-direction decoded frames.
func HandleCoAP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxCoAPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedCoAP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("coap", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedCoAP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "coap"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		events = append(events, parsedCoAP{Direction: "read", Payload: payload, CodeName: "UNKNOWN", Command: "UNKNOWN"})
		return nil
	}

	frame, msg, err := parseCoAP(payload)
	frame.Truncated = len(data) > maxCoAPPayload
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse CoAP message",
			slog.String("protocol", "coap"),
			producer.ErrAttr(err),
			slog.Int("bytes", len(payload)),
		)
		return nil
	}

	logger.Info("CoAP UDP packet received",
		slog.String("handler", "coap"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("type", frame.Type),
		slog.String("code", frame.CodeName),
		slog.String("path", frame.Path),
	)

	resp, writeFrame, ok := buildCoAPReply(msg)
	if !ok {
		return nil
	}
	events = append(events, writeFrame)
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to reply to CoAP request", slog.String("protocol", "coap"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return err
	}
	return nil
}
