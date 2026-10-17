// Package radius parses RADIUS (RFC 2865/2866) datagrams and builds the
// minimal replies Glutton sends. It does no I/O.
package radius

import (
	"crypto/md5" //nolint:gosec // RFC 2865 mandates MD5 for authenticators
	"encoding/binary"
	"errors"
	"strconv"
)

const (
	headerLen = 20
	maxLength = 4096 // RFC 2865 §3

	CodeAccessRequest      = 1
	CodeAccessAccept       = 2
	CodeAccessReject       = 3
	CodeAccountingRequest  = 4
	CodeAccountingResponse = 5
	CodeAccessChallenge    = 11
	CodeStatusServer       = 12
	CodeStatusClient       = 13

	AttrUserName             = 1
	AttrUserPassword         = 2
	AttrCHAPPassword         = 3
	AttrNASIPAddress         = 4
	AttrCalledStationID      = 30
	AttrCallingStationID     = 31
	AttrNASIdentifier        = 32
	AttrMessageAuthenticator = 80
)

// replySecret keys the Response Authenticator. Clients that do not know it
// cannot verify the reply, which scanners do not do either.
const replySecret = "radius"

// guessSecrets are the shared secrets tried when decrypting User-Password.
var guessSecrets = []string{"testing123", "secret", "radius", "password", "sharedsecret", "cisco", "mysecret", "changeme", ""}

var (
	ErrShort  = errors.New("radius: datagram shorter than header")
	ErrLength = errors.New("radius: bad length field")
	ErrAttr   = errors.New("radius: malformed attribute")
)

var codeNames = map[byte]string{
	CodeAccessRequest:      "Access-Request",
	CodeAccessAccept:       "Access-Accept",
	CodeAccessReject:       "Access-Reject",
	CodeAccountingRequest:  "Accounting-Request",
	CodeAccountingResponse: "Accounting-Response",
	CodeAccessChallenge:    "Access-Challenge",
	CodeStatusServer:       "Status-Server",
	CodeStatusClient:       "Status-Client",
}

// Attr is one type-length-value attribute.
type Attr struct {
	Type  byte
	Value []byte
}

// Packet is a parsed RADIUS packet. Attrs holds every attribute that parsed
// before an error, if any.
type Packet struct {
	Code          byte
	ID            byte
	Length        int
	Authenticator [16]byte
	Attrs         []Attr
}

// CodeName returns the RFC name of a packet code, or "code_N".
func CodeName(code byte) string {
	if n, ok := codeNames[code]; ok {
		return n
	}
	return "code_" + strconv.Itoa(int(code))
}

// Parse decodes a RADIUS datagram. Bytes past the length field are ignored,
// as RFC 2865 §3 requires. On ErrAttr the returned Packet still carries the
// header and the attributes parsed so far.
func Parse(data []byte) (Packet, error) {
	if len(data) < headerLen {
		return Packet{}, ErrShort
	}
	p := Packet{Code: data[0], ID: data[1], Length: int(binary.BigEndian.Uint16(data[2:4]))}
	copy(p.Authenticator[:], data[4:20])
	if p.Length < headerLen || p.Length > maxLength || p.Length > len(data) {
		return p, ErrLength
	}
	body := data[headerLen:p.Length]
	for len(body) > 0 {
		if len(body) < 2 || body[1] < 2 || int(body[1]) > len(body) {
			return p, ErrAttr
		}
		n := int(body[1])
		p.Attrs = append(p.Attrs, Attr{Type: body[0], Value: body[2:n]})
		body = body[n:]
	}
	return p, nil
}

// Find returns the first attribute of the given type.
func (p Packet) Find(t byte) ([]byte, bool) {
	for _, a := range p.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// DecryptPassword reverses the RFC 2865 §5.2 User-Password hiding with each
// guess secret and returns the first result that is printable text.
func DecryptPassword(auth [16]byte, hidden []byte) (string, bool) {
	if len(hidden) == 0 || len(hidden)%16 != 0 || len(hidden) > 128 {
		return "", false
	}
	for _, secret := range guessSecrets {
		out := make([]byte, 0, len(hidden))
		prev := auth[:]
		for i := 0; i < len(hidden); i += 16 {
			sum := md5.Sum(append([]byte(secret), prev...)) //nolint:gosec
			for j := 0; j < 16; j++ {
				out = append(out, hidden[i+j]^sum[j])
			}
			prev = hidden[i : i+16]
		}
		for len(out) > 0 && out[len(out)-1] == 0 {
			out = out[:len(out)-1]
		}
		if printable(out) {
			return string(out), true
		}
	}
	return "", false
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// Reply builds the response to req, or nil when the packet is only recorded.
// Access-Request gets Access-Reject, Accounting-Request gets
// Accounting-Response and Status-Server gets Access-Accept. Replies are bare
// 20-byte headers, never larger than the request.
func Reply(req Packet) []byte {
	var code byte
	switch req.Code {
	case CodeAccessRequest:
		code = CodeAccessReject
	case CodeAccountingRequest:
		code = CodeAccountingResponse
	case CodeStatusServer:
		code = CodeAccessAccept
	default:
		return nil
	}
	resp := make([]byte, headerLen)
	resp[0], resp[1] = code, req.ID
	binary.BigEndian.PutUint16(resp[2:4], headerLen)
	copy(resp[4:], req.Authenticator[:])
	sum := md5.Sum(append(resp, replySecret...)) //nolint:gosec
	copy(resp[4:], sum[:])
	return resp
}
