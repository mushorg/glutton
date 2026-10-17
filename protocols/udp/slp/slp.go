// Package slp parses Service Location Protocol v2 (RFC 2608) requests and
// builds the minimal replies the honeypot sends. It does no I/O.
package slp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Function IDs (RFC 2608 section 8).
const (
	FuncSrvRqst     = 1
	FuncSrvRply     = 2
	FuncSrvReg      = 3
	FuncSrvDeReg    = 4
	FuncSrvAck      = 5
	FuncAttrRqst    = 6
	FuncAttrRply    = 7
	FuncDAAdvert    = 8
	FuncSrvTypeRqst = 9
	FuncSrvTypeRply = 10
	FuncSAAdvert    = 11
)

// Error codes (RFC 2608 section 7).
const (
	ErrOK                = 0
	ErrScopeNotSupported = 4
)

// FlagMulticast is the REQUEST MULTICAST bit of the flags field.
const FlagMulticast = 0x2000

// DefaultScope is the scope every SLP agent supports.
const DefaultScope = "default"

const fixedHeader = 14

var (
	ErrShort   = errors.New("slp: short header")
	ErrVersion = errors.New("slp: not SLPv2")
	ErrLength  = errors.New("slp: length field does not match datagram")
	ErrBody    = errors.New("slp: malformed body")
)

// Header is the SLPv2 common header.
type Header struct {
	Function  uint8
	Length    uint32
	Flags     uint16
	ExtOffset uint32
	XID       uint16
	Lang      string
	// bodyOff is where the function-specific body starts.
	bodyOff int
}

// Request holds the string fields of the requests we parse.
type Request struct {
	ServiceType string // SrvRqst service type, SrvTypeRqst naming authority
	Scope       string
	Predicate   string
	URL         string // AttrRqst URL or service type
}

var functionNames = map[uint8]string{
	FuncSrvRqst: "SrvRqst", FuncSrvRply: "SrvRply", FuncSrvReg: "SrvReg",
	FuncSrvDeReg: "SrvDeReg", FuncSrvAck: "SrvAck", FuncAttrRqst: "AttrRqst",
	FuncAttrRply: "AttrRply", FuncDAAdvert: "DAAdvert",
	FuncSrvTypeRqst: "SrvTypeRqst", FuncSrvTypeRply: "SrvTypeRply",
	FuncSAAdvert: "SAAdvert",
}

// FunctionName returns the RFC name of a function ID.
func FunctionName(f uint8) string {
	if n, ok := functionNames[f]; ok {
		return n
	}
	return fmt.Sprintf("function_%d", f)
}

var errorNames = map[uint16]string{
	0: "OK", 1: "LANGUAGE_NOT_SUPPORTED", 2: "PARSE_ERROR", 3: "INVALID_REGISTRATION",
	4: "SCOPE_NOT_SUPPORTED", 6: "AUTHENTICATION_UNKNOWN", 7: "AUTHENTICATION_ABSENT",
	8: "AUTHENTICATION_FAILED", 13: "INVALID_UPDATE", 14: "REFRESH_REJECTED",
}

// ErrorName returns the RFC name of an error code.
func ErrorName(c uint16) string {
	if n, ok := errorNames[c]; ok {
		return n
	}
	return fmt.Sprintf("error_%d", c)
}

// ParseHeader decodes the common header. The length field must equal the
// datagram length; on ErrLength or ErrBody the returned header is still
// populated so the caller can record what was readable.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < fixedHeader {
		return Header{}, ErrShort
	}
	if b[0] != 2 {
		return Header{}, ErrVersion
	}
	h := Header{
		Function:  b[1],
		Length:    uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4]),
		Flags:     binary.BigEndian.Uint16(b[5:7]),
		ExtOffset: uint32(b[7])<<16 | uint32(b[8])<<8 | uint32(b[9]),
		XID:       binary.BigEndian.Uint16(b[10:12]),
	}
	if int(h.Length) != len(b) {
		return h, ErrLength
	}
	langLen := int(binary.BigEndian.Uint16(b[12:14]))
	if fixedHeader+langLen > len(b) {
		return h, ErrBody
	}
	h.Lang = string(b[fixedHeader : fixedHeader+langLen])
	h.bodyOff = fixedHeader + langLen
	return h, nil
}

// reader walks length-prefixed (uint16) strings with bounds checks.
type reader struct {
	b   []byte
	err error
}

func (r *reader) str() string {
	if r.err != nil {
		return ""
	}
	if len(r.b) < 2 {
		r.err = ErrBody
		return ""
	}
	n := int(binary.BigEndian.Uint16(r.b))
	if len(r.b) < 2+n {
		r.err = ErrBody
		return ""
	}
	s := string(r.b[2 : 2+n])
	r.b = r.b[2+n:]
	return s
}

// ParseRequest decodes the body of SrvRqst, SrvTypeRqst and AttrRqst. h must
// come from a successful ParseHeader of b.
func ParseRequest(b []byte, h Header) (Request, error) {
	r := &reader{b: b[h.bodyOff:]}
	var q Request
	switch h.Function {
	case FuncSrvRqst:
		r.str() // previous responder list
		q.ServiceType = r.str()
		q.Scope = r.str()
		q.Predicate = r.str()
		r.str() // SPI
	case FuncSrvTypeRqst:
		r.str() // previous responder list
		q.ServiceType = r.str()
		q.Scope = r.str()
	case FuncAttrRqst:
		r.str() // previous responder list
		q.URL = r.str()
		q.Scope = r.str()
		r.str() // tag list
		r.str() // SPI
	default:
		return q, nil
	}
	return q, r.err
}

// SupportsScope reports whether the comma-separated scope list names the
// default scope.
func SupportsScope(scopes string) bool {
	for _, s := range strings.Split(scopes, ",") {
		if strings.EqualFold(strings.TrimSpace(s), DefaultScope) {
			return true
		}
	}
	return false
}

// header builds a reply header with room for bodyLen more bytes.
func header(fn uint8, xid uint16, lang string, bodyLen int) []byte {
	total := fixedHeader + len(lang) + bodyLen
	b := make([]byte, fixedHeader+len(lang), total)
	b[0] = 2
	b[1] = fn
	b[2], b[3], b[4] = byte(total>>16), byte(total>>8), byte(total)
	binary.BigEndian.PutUint16(b[10:12], xid)
	binary.BigEndian.PutUint16(b[12:14], uint16(len(lang)))
	copy(b[fixedHeader:], lang)
	return b
}

// Reply builds the reply to a parsed request and its error code, or nil if
// the function gets none. Requests for scopes other than "default" get
// SCOPE_NOT_SUPPORTED; otherwise the answer is empty (no services, types or
// attributes), so a reply is smaller than the request that triggered it.
// Multicast requests are never answered.
func Reply(h Header, q Request) (reply []byte, errCode uint16) {
	if h.Flags&FlagMulticast != 0 {
		return nil, 0
	}
	if !SupportsScope(q.Scope) {
		errCode = ErrScopeNotSupported
	}
	switch h.Function {
	case FuncSrvRqst:
		// error code, URL entry count
		b := header(FuncSrvRply, h.XID, h.Lang, 4)
		b = binary.BigEndian.AppendUint16(b, errCode)
		return binary.BigEndian.AppendUint16(b, 0), errCode
	case FuncSrvTypeRqst:
		// error code, empty type list
		b := header(FuncSrvTypeRply, h.XID, h.Lang, 4)
		b = binary.BigEndian.AppendUint16(b, errCode)
		return binary.BigEndian.AppendUint16(b, 0), errCode
	case FuncAttrRqst:
		// error code, empty attribute list, no auth blocks
		b := header(FuncAttrRply, h.XID, h.Lang, 5)
		b = binary.BigEndian.AppendUint16(b, errCode)
		b = binary.BigEndian.AppendUint16(b, 0)
		return append(b, 0), errCode
	}
	return nil, 0
}
