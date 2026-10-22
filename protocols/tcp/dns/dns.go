// Package dns parses DNS queries (RFC 1035, EDNS0 per RFC 6891) and builds the
// refusals a non-recursive name server sends. It never resolves anything.
package dns

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// MaxMessage is the largest message a two-byte TCP length prefix can carry.
const MaxMessage = 65535

const (
	headerLen = 12
	maxName   = 255
	maxLabel  = 63
	// ednsSize is the UDP payload size advertised in the OPT echo, as BIND
	// and Unbound do by default.
	ednsSize = 1232
)

// Response codes (RFC 1035 §4.1.1, RFC 6891 §9 for BADVERS).
const (
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNotImp   = 4
	RcodeRefused  = 5
	RcodeBadVers  = 16
)

const typeOPT = 41

var rcodeNames = map[int]string{
	RcodeNoError:  "NOERROR",
	RcodeFormErr:  "FORMERR",
	RcodeServFail: "SERVFAIL",
	RcodeNotImp:   "NOTIMP",
	RcodeRefused:  "REFUSED",
	RcodeBadVers:  "BADVERS",
}

var typeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY",
	257: "CAA",
}

var classNames = map[uint16]string{1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

// RcodeName returns the mnemonic for a response code.
func RcodeName(rcode int) string {
	if n, ok := rcodeNames[rcode]; ok {
		return n
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// TypeName returns the mnemonic for a query type (RFC 3597 TYPEnnn if unknown).
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ClassName returns the mnemonic for a query class (CLASSnnn if unknown).
func ClassName(c uint16) string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// Query is the parsed form of one DNS message.
type Query struct {
	ID       uint16
	Response bool   // QR bit: the client sent a response, which gets no answer
	Opcode   uint8  // 0 query, 1 iquery, 2 status, 4 notify, 5 update
	RD       bool   // recursion desired, copied into the reply
	Name     string // first question name, dotted, "." for the root
	Type     uint16
	Class    uint16
	EDNS     bool  // an OPT record is present
	Version  uint8 // EDNS version
	// Question is the wire form of the first question (name, type, class),
	// echoed into the reply as the client sent it.
	Question []byte
}

// ErrShort and ErrMalformed describe queries that cannot be answered with a
// question echo. Parse still returns the header fields when it can.
var (
	ErrShort     = errors.New("dns: message shorter than header")
	ErrMalformed = errors.New("dns: malformed message")
)

// Parse decodes one DNS message (without the TCP length prefix). With
// ErrMalformed the ID, flags and opcode in the result are valid, so the
// caller can still send FORMERR; with ErrShort nothing is.
func Parse(msg []byte) (Query, error) {
	var q Query
	if len(msg) < headerLen {
		return q, ErrShort
	}
	q.ID = binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	q.Response = flags&0x8000 != 0
	q.Opcode = uint8(flags >> 11 & 0xf)
	q.RD = flags&0x0100 != 0
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	ns := binary.BigEndian.Uint16(msg[8:10])
	ar := binary.BigEndian.Uint16(msg[10:12])
	if qd != 1 {
		return q, ErrMalformed
	}

	name, off, err := readName(msg, headerLen)
	if err != nil || off+4 > len(msg) {
		return q, ErrMalformed
	}
	q.Name = name
	q.Type = binary.BigEndian.Uint16(msg[off : off+2])
	q.Class = binary.BigEndian.Uint16(msg[off+2 : off+4])
	off += 4
	q.Question = append([]byte(nil), msg[headerLen:off]...)

	// A query carries no answer or authority records; only look for OPT in
	// the additional section when that holds.
	if an != 0 || ns != 0 {
		return q, nil
	}
	for i := 0; i < int(ar) && i < 8; i++ {
		_, next, err := readName(msg, off)
		if err != nil || next+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		if next+10+rdLen > len(msg) {
			break
		}
		if rrType == typeOPT {
			q.EDNS = true
			q.Version = uint8(ttl >> 16)
			break
		}
		off = next + 10 + rdLen
	}
	return q, nil
}

// readName reads an uncompressed name at off. Compression pointers are not
// valid in a question and are rejected, which also rules out pointer loops.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	total := 0
	for {
		if off >= len(msg) {
			return "", 0, ErrMalformed
		}
		n := int(msg[off])
		off++
		if n == 0 {
			break
		}
		if n > maxLabel || off+n > len(msg) {
			return "", 0, ErrMalformed
		}
		total += n + 1
		if total > maxName {
			return "", 0, ErrMalformed
		}
		labels = append(labels, escapeLabel(msg[off:off+n]))
		off += n
	}
	if len(labels) == 0 {
		return ".", off, nil
	}
	return strings.Join(labels, "."), off, nil
}

// escapeLabel keeps names printable in logs: bytes outside 0x21-0x7e and the
// label separator are written as \DDD (RFC 1035 §5.1).
func escapeLabel(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < 0x21 || c > 0x7e || c == '.' || c == '\\' {
			sb.WriteString("\\" + pad3(int(c)))
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func pad3(n int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", 3-len(s)) + s
}

// Refusal picks the response code a non-recursive server gives q: NOTIMP for
// opcodes other than QUERY, BADVERS for an unsupported EDNS version, FORMERR
// for a malformed question, and REFUSED for every real query (including AXFR
// and recursion requests), since the honeypot is authoritative for nothing.
func Refusal(q Query, parseErr error) int {
	switch {
	case parseErr != nil:
		return RcodeFormErr
	case q.Opcode != 0:
		return RcodeNotImp
	case q.EDNS && q.Version != 0:
		return RcodeBadVers
	}
	return RcodeRefused
}

// BuildResponse builds the reply to q with response code rcode. The question
// is echoed, an EDNS query gets an empty OPT record back, recursion is never
// offered (RA clear) and no records are returned, so the reply is never
// larger than the query. A query that failed to parse gets a bare header.
func BuildResponse(q Query, rcode int, parseErr error) []byte {
	flags := uint16(0x8000) | uint16(q.Opcode&0xf)<<11 | uint16(rcode&0xf)
	if q.RD {
		flags |= 0x0100
	}
	withQuestion := parseErr == nil
	msg := make([]byte, headerLen, headerLen+len(q.Question)+11)
	binary.BigEndian.PutUint16(msg[0:2], q.ID)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	if withQuestion {
		binary.BigEndian.PutUint16(msg[4:6], 1)
		msg = append(msg, q.Question...)
	}
	if withQuestion && q.EDNS {
		binary.BigEndian.PutUint16(msg[10:12], 1)
		// root name, OPT, UDP size, extended rcode + version 0 + flags, no RDATA
		opt := []byte{0, 0, typeOPT, 0, 0, byte(rcode >> 4), 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(opt[3:5], ednsSize)
		msg = append(msg, opt...)
	}
	return msg
}
