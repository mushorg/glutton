package postgres

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// SQLSTATE codes of the errors the server sends.
const (
	StateInvalidPassword      = "28P01"
	StateInvalidAuthorization = "28000"
	StateProtocolViolation    = "08P01"
	StateFeatureNotSupported  = "0A000"
)

const (
	authRequestMD5 = 5
	// protocolOptionPrefix marks protocol extension options in a
	// StartupMessage; the server supports none.
	protocolOptionPrefix = "_pq_."
)

// NotSupported is the single-byte answer to SSLRequest and GSSENCRequest
// that tells the client to continue in plaintext.
var NotSupported = []byte{'N'}

// message frames body as a typed backend message.
func message(t byte, body []byte) []byte {
	b := make([]byte, 0, 5+len(body))
	b = append(b, t)
	b = binary.BigEndian.AppendUint32(b, uint32(4+len(body)))
	return append(b, body...)
}

// BuildAuthMD5 builds AuthenticationMD5Password with the given salt.
func BuildAuthMD5(salt [4]byte) []byte {
	body := binary.BigEndian.AppendUint32(nil, authRequestMD5)
	return message('R', append(body, salt[:]...))
}

// BuildNegotiateProtocolVersion tells a client that asked for 3.x (x > 0) or
// sent _pq_. protocol options that the server speaks 3.0 and none of them.
func BuildNegotiateProtocolVersion(unsupported []string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 0)
	body = binary.BigEndian.AppendUint32(body, uint32(len(unsupported)))
	for _, opt := range unsupported {
		body = append(body, opt...)
		body = append(body, 0)
	}
	return message('v', body)
}

// UnsupportedOptions returns the _pq_. protocol options among params.
func UnsupportedOptions(params []Param) []string {
	var opts []string
	for _, p := range params {
		if strings.HasPrefix(p.Name, protocolOptionPrefix) {
			opts = append(opts, p.Name)
		}
	}
	return opts
}

// Error is a FATAL ErrorResponse. File, Line and Routine name the server
// source location real servers report; the line numbers approximate a
// PostgreSQL 15 build and are not checked against its source.
type Error struct {
	Code    string
	Message string
	File    string
	Line    int
	Routine string
}

// Build encodes the ErrorResponse with the fields in the order a server
// sends them.
func (e Error) Build() []byte {
	var body []byte
	field := func(t byte, v string) {
		body = append(body, t)
		body = append(body, v...)
		body = append(body, 0)
	}
	field('S', "FATAL")
	field('V', "FATAL")
	field('C', e.Code)
	field('M', e.Message)
	field('F', e.File)
	field('L', strconv.Itoa(e.Line))
	field('R', e.Routine)
	body = append(body, 0)
	return message('E', body)
}

// PasswordFailed is the reply to a wrong password under md5 auth.
func PasswordFailed(user string) Error {
	return Error{
		Code:    StateInvalidPassword,
		Message: `password authentication failed for user "` + user + `"`,
		File:    "auth.c",
		Line:    330,
		Routine: "auth_failed",
	}
}

// UnsupportedProtocol is the reply to a StartupMessage for a protocol other
// than 3.x.
func UnsupportedProtocol(major, minor uint16) Error {
	return Error{
		Code:    StateFeatureNotSupported,
		Message: fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", major, minor),
		File:    "postmaster.c",
		Line:    2210,
		Routine: "ProcessStartupPacket",
	}
}

// NoUser is the reply to a StartupMessage without a user parameter.
func NoUser() Error {
	return Error{
		Code:    StateInvalidAuthorization,
		Message: "no PostgreSQL user name specified in startup packet",
		File:    "postmaster.c",
		Line:    2290,
		Routine: "ProcessStartupPacket",
	}
}

// ExpectedPassword is the reply to a message other than PasswordMessage
// while the server waits for the password.
func ExpectedPassword(t byte) Error {
	return Error{
		Code:    StateProtocolViolation,
		Message: fmt.Sprintf("expected password response, got message type %d", t),
		File:    "auth.c",
		Line:    704,
		Routine: "recv_password_packet",
	}
}
