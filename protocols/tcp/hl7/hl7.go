// Package hl7 parses HL7 v2 messages and builds acknowledgements. Messages
// arrive wrapped in the Minimal Lower Layer Protocol (MLLP): a 0x0B start
// block, segments separated by CR, then 0x1C 0x0D. Some clients (and the
// medpot honeypot's test sender) skip the framing and send the bare message.
package hl7

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

const (
	StartBlock = 0x0B
	EndBlock   = 0x1C
	CR         = 0x0D

	// maxSegmentIDs bounds the segment list recorded for one message.
	maxSegmentIDs = 100

	defaultEncoding   = `^~\&`
	defaultVersion    = "2.5"
	defaultProcessing = "P"
)

// HL7 table 0357 error codes used in ERR-3.
const (
	ErrorSegmentSequence = "100"
	ErrorRequiredField   = "101"
)

var errorText = map[string]string{
	ErrorSegmentSequence: "Segment sequence error",
	ErrorRequiredField:   "Required field missing",
}

var (
	// ErrNoMSH means the message does not start with an MSH segment.
	ErrNoMSH = errors.New("hl7: message does not start with MSH")
	// ErrTooLarge means the message exceeded the read cap.
	ErrTooLarge = errors.New("hl7: message too large")
)

// Header holds the MSH fields the honeypot records and echoes.
type Header struct {
	FieldSep             byte
	Encoding             string // MSH-2
	SendingApplication   string // MSH-3
	SendingFacility      string // MSH-4
	ReceivingApplication string // MSH-5
	ReceivingFacility    string // MSH-6
	Security             string // MSH-8
	MessageCode          string // MSH-9.1
	TriggerEvent         string // MSH-9.2
	ControlID            string // MSH-10
	ProcessingID         string // MSH-11
	Version              string // MSH-12.1
}

// MessageType is MSH-9 as code^trigger, or just the code without a trigger.
func (h Header) MessageType() string {
	if h.TriggerEvent == "" {
		return h.MessageCode
	}
	return h.MessageCode + "^" + h.TriggerEvent
}

// ReadMessage reads one message. An MLLP frame is read up to its end block;
// a bare message is whatever the client sent in one go. raw holds the wire
// bytes (framing included), msg the HL7 content. At most max content bytes
// are kept; a longer message returns truncated and ErrTooLarge.
func ReadMessage(r *bufio.Reader, max int) (raw, msg []byte, framed, truncated bool, err error) {
	first, err := r.Peek(1)
	// skip line ends left between messages (a CR that trailed an end block)
	for err == nil && (first[0] == CR || first[0] == '\n') {
		_, _ = r.Discard(1)
		first, err = r.Peek(1)
	}
	if err != nil {
		return nil, nil, false, false, err
	}
	if first[0] != StartBlock {
		raw, truncated, err = readBare(r, max)
		return raw, raw, false, truncated, err
	}
	raw, msg, truncated, err = readFramed(r, max)
	return raw, msg, true, truncated, err
}

func readFramed(r *bufio.Reader, max int) (raw, msg []byte, truncated bool, err error) {
	start, _ := r.ReadByte()
	raw = []byte{start}
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return raw, raw[1:], false, err
		}
		if b == EndBlock {
			raw = append(raw, b)
			end := len(raw) - 1
			// the CR completes the frame; take it only if it already arrived
			// so a sender that omits it still gets its ACK right away
			if r.Buffered() > 0 {
				if next, _ := r.Peek(1); next[0] == CR {
					raw = append(raw, CR)
					_, _ = r.Discard(1)
				}
			}
			return raw, raw[1:end], false, nil
		}
		if len(raw)-1 >= max {
			return raw, raw[1:], true, ErrTooLarge
		}
		raw = append(raw, b)
	}
}

func readBare(r *bufio.Reader, max int) ([]byte, bool, error) {
	n := r.Buffered()
	truncated := n > max
	if truncated {
		n = max
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return raw, false, err
	}
	if truncated {
		_, _ = r.Discard(r.Buffered())
		return raw, true, ErrTooLarge
	}
	return raw, false, nil
}

// segments splits a message on CR, LF or CRLF and drops empty lines.
func segments(msg []byte) [][]byte {
	lines := bytes.FieldsFunc(msg, func(r rune) bool { return r == '\r' || r == '\n' })
	out := lines[:0]
	for _, l := range lines {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// ParseMSH parses the MSH segment at the start of msg. Missing fields are
// left empty; only a message that does not start with MSH is an error.
func ParseMSH(msg []byte) (Header, error) {
	segs := segments(msg)
	if len(segs) == 0 {
		return Header{}, ErrNoMSH
	}
	msh := bytes.TrimLeft(segs[0], " \t")
	if len(msh) < 4 || !bytes.HasPrefix(msh, []byte("MSH")) {
		return Header{}, ErrNoMSH
	}
	h := Header{FieldSep: msh[3]}
	// fields[0] is "MSH" and MSH-1 is the separator itself, so fields[i]
	// holds MSH-(i+1)
	fields := strings.Split(string(msh), string(h.FieldSep))
	field := func(n int) string {
		if n-1 < len(fields) {
			return fields[n-1]
		}
		return ""
	}
	h.Encoding = field(2)
	comp := "^"
	if h.Encoding != "" {
		comp = h.Encoding[:1]
	}
	component := func(v string, n int) string {
		parts := strings.Split(v, comp)
		if n-1 < len(parts) {
			return parts[n-1]
		}
		return ""
	}
	h.SendingApplication = field(3)
	h.SendingFacility = field(4)
	h.ReceivingApplication = field(5)
	h.ReceivingFacility = field(6)
	h.Security = field(8)
	h.MessageCode = component(field(9), 1)
	h.TriggerEvent = component(field(9), 2)
	h.ControlID = field(10)
	h.ProcessingID = field(11)
	h.Version = component(field(12), 1)
	return h, nil
}

// SegmentIDs lists the segment IDs of msg in order, capped at maxSegmentIDs.
func SegmentIDs(msg []byte, sep byte) []string {
	if sep == 0 {
		sep = '|'
	}
	var ids []string
	for _, seg := range segments(msg) {
		if len(ids) == maxSegmentIDs {
			break
		}
		id := seg
		if i := bytes.IndexByte(seg, sep); i >= 0 {
			id = seg[:i]
		}
		id = bytes.TrimSpace(id)
		if len(id) > 3 {
			id = id[:3]
		}
		ids = append(ids, string(id))
	}
	return ids
}

// Ack describes an acknowledgement to a request.
type Ack struct {
	Code      string // MSA-1: AA, AE or AR
	ControlID string // MSH-10 of the ACK itself
	Timestamp string // MSH-7, HL7 DTM
	ErrorCode string // HL7 table 0357 code for the ERR segment on AE/AR
}

// AckHeader is the MSH of the acknowledgement: sender and receiver swapped,
// separators, processing ID and version echoed from the request.
func AckHeader(req Header, ack Ack) Header {
	h := Header{
		FieldSep:             req.FieldSep,
		Encoding:             req.Encoding,
		SendingApplication:   req.ReceivingApplication,
		SendingFacility:      req.ReceivingFacility,
		ReceivingApplication: req.SendingApplication,
		ReceivingFacility:    req.SendingFacility,
		MessageCode:          "ACK",
		TriggerEvent:         req.TriggerEvent,
		ControlID:            ack.ControlID,
		ProcessingID:         req.ProcessingID,
		Version:              req.Version,
	}
	if h.FieldSep == 0 {
		h.FieldSep = '|'
	}
	if len(h.Encoding) < 4 {
		h.Encoding = defaultEncoding
	}
	if h.ProcessingID == "" {
		h.ProcessingID = defaultProcessing
	}
	if h.Version == "" {
		h.Version = defaultVersion
	}
	return h
}

// BuildACK builds the acknowledgement message (without MLLP framing).
func BuildACK(req Header, ack Ack) []byte {
	h := AckHeader(req, ack)
	sep := string(h.FieldSep)
	comp := h.Encoding[:1]
	msgType := "ACK"
	if h.TriggerEvent != "" {
		msgType += comp + h.TriggerEvent
		// MSH-9.3 message structure exists from v2.3.1 on
		if !strings.HasPrefix(h.Version, "2.1") && !strings.HasPrefix(h.Version, "2.2") && h.Version != "2.3" {
			msgType += comp + "ACK"
		}
	}
	var b bytes.Buffer
	b.WriteString(strings.Join([]string{
		"MSH", h.Encoding, h.SendingApplication, h.SendingFacility,
		h.ReceivingApplication, h.ReceivingFacility, ack.Timestamp, "",
		msgType, h.ControlID, h.ProcessingID, h.Version,
	}, sep))
	b.WriteByte(CR)
	b.WriteString(strings.Join([]string{"MSA", ack.Code, req.ControlID}, sep))
	b.WriteByte(CR)
	if ack.ErrorCode != "" {
		code := strings.Join([]string{ack.ErrorCode, errorText[ack.ErrorCode], "HL70357"}, comp)
		b.WriteString(strings.Join([]string{"ERR", "", "", code, "E"}, sep))
		b.WriteByte(CR)
	}
	return b.Bytes()
}

// Frame wraps msg in an MLLP block.
func Frame(msg []byte) []byte {
	out := make([]byte, 0, len(msg)+3)
	out = append(out, StartBlock)
	out = append(out, msg...)
	return append(out, EndBlock, CR)
}

// LooksLikeHL7 reports whether b starts an HL7 v2 message: an MLLP start
// block followed by MSH, or a bare "MSH|".
func LooksLikeHL7(b []byte) bool {
	if len(b) >= 4 && b[0] == StartBlock {
		return bytes.HasPrefix(b[1:], []byte("MSH"))
	}
	return bytes.HasPrefix(b, []byte("MSH|"))
}
