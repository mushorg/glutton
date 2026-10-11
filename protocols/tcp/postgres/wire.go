// Package postgres parses the PostgreSQL frontend/backend protocol (version
// 3.0, https://www.postgresql.org/docs/current/protocol-message-formats.html)
// far enough to answer SSL/GSS negotiation and the startup packet and to
// record the password message, and builds the server replies.
package postgres

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Request codes of the untyped first messages.
const (
	CancelRequestCode = 80877102 // 1234 << 16 | 5678
	SSLRequestCode    = 80877103 // 1234 << 16 | 5679
	GSSENCRequestCode = 80877104 // 1234 << 16 | 5680
	ProtocolVersion3  = 3 << 16
)

const (
	// MaxStartupLen is the server's MAX_STARTUP_PACKET_LENGTH.
	MaxStartupLen = 10000
	// minStartupLen is the length and code fields alone.
	minStartupLen = 8
	// PeekLen covers the length and code of an untyped first message.
	PeekLen = 8
)

var (
	// ErrTooLong is returned when a message would pass the read cap.
	ErrTooLong = errors.New("postgres message exceeds cap")
	// ErrMalformed is returned for a message whose fields cannot be valid.
	ErrMalformed = errors.New("malformed postgres message")
)

// Startup is an untyped first message: SSLRequest, GSSENCRequest,
// CancelRequest or StartupMessage.
type Startup struct {
	Raw  []byte // the message as read, length field included
	Code uint32
}

// Name returns the command name for the startup code. Any code that is not a
// negotiation or cancel request is a StartupMessage for that protocol version.
func (s Startup) Name() string {
	switch s.Code {
	case SSLRequestCode:
		return "SSLRequest"
	case GSSENCRequestCode:
		return "GSSENCRequest"
	case CancelRequestCode:
		return "CancelRequest"
	}
	return "StartupMessage"
}

// Version returns the protocol version of a StartupMessage as major, minor.
func (s Startup) Version() (major, minor uint16) {
	return uint16(s.Code >> 16), uint16(s.Code)
}

// Body returns the bytes after the length and code.
func (s Startup) Body() []byte {
	if len(s.Raw) < minStartupLen {
		return nil
	}
	return s.Raw[minStartupLen:]
}

// ReadStartup reads one untyped message. On error Raw holds the bytes read
// so far.
func ReadStartup(r *bufio.Reader, maxLen int) (Startup, error) {
	header := make([]byte, minStartupLen)
	n, err := io.ReadFull(r, header[:4])
	if err != nil {
		return Startup{Raw: header[:n]}, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length < minStartupLen {
		return Startup{Raw: header[:4]}, ErrMalformed
	}
	if length > maxLen {
		return Startup{Raw: header[:4]}, ErrTooLong
	}
	n, err = io.ReadFull(r, header[4:])
	if err != nil {
		return Startup{Raw: header[:4+n]}, err
	}
	s := Startup{Code: binary.BigEndian.Uint32(header[4:])}
	raw := make([]byte, length)
	copy(raw, header)
	n, err = io.ReadFull(r, raw[minStartupLen:])
	s.Raw = raw[:minStartupLen+n]
	return s, err
}

// Param is one StartupMessage parameter.
type Param struct {
	Name  string
	Value string
}

// ParseParams parses the NUL-terminated name/value pairs of a StartupMessage
// body, which ends with an empty name.
func ParseParams(body []byte) ([]Param, error) {
	var params []Param
	for {
		name, rest, ok := bytes.Cut(body, []byte{0})
		if !ok {
			return params, ErrMalformed
		}
		if len(name) == 0 {
			if len(rest) != 0 {
				return params, ErrMalformed
			}
			return params, nil
		}
		value, rest, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return params, ErrMalformed
		}
		params = append(params, Param{Name: string(name), Value: string(value)})
		body = rest
	}
}

// Message is a typed frontend message.
type Message struct {
	Raw  []byte // type byte, length and body as read
	Type byte
}

// Body returns the bytes after the type and length.
func (m Message) Body() []byte {
	if len(m.Raw) < 5 {
		return nil
	}
	return m.Raw[5:]
}

// Password returns the string of a PasswordMessage as sent (cleartext, or
// "md5" and the hex hash under md5 auth), up to its NUL terminator.
func (m Message) Password() string {
	pw, _, _ := bytes.Cut(m.Body(), []byte{0})
	return string(pw)
}

// ReadMessage reads one typed message. On error Raw holds the bytes read so
// far.
func ReadMessage(r *bufio.Reader, maxLen int) (Message, error) {
	header := make([]byte, 5)
	n, err := io.ReadFull(r, header)
	if n == 0 {
		return Message{}, err
	}
	m := Message{Type: header[0], Raw: header[:n]}
	if err != nil {
		return m, err
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length < 4 {
		return m, ErrMalformed
	}
	if length > maxLen {
		return m, ErrTooLong
	}
	raw := make([]byte, 1+length)
	copy(raw, header)
	n, err = io.ReadFull(r, raw[5:])
	m.Raw = raw[:5+n]
	return m, err
}

var messageNames = map[byte]string{
	'B': "Bind",
	'C': "Close",
	'D': "Describe",
	'E': "Execute",
	'F': "FunctionCall",
	'H': "Flush",
	'P': "Parse",
	'Q': "Query",
	'S': "Sync",
	'X': "Terminate",
	'c': "CopyDone",
	'd': "CopyData",
	'f': "CopyFail",
	'p': "PasswordMessage",
}

// MessageName returns the command name for a frontend message type.
func MessageName(t byte) string {
	if name, ok := messageNames[t]; ok {
		return name
	}
	return fmt.Sprintf("type_0x%02x", t)
}

// MayStart reports whether the first four bytes are a plausible length of an
// untyped first message.
func MayStart(snip []byte) bool {
	if len(snip) < 4 {
		return false
	}
	length := binary.BigEndian.Uint32(snip)
	return length >= minStartupLen && length <= MaxStartupLen
}

// LooksLikeStartup reports whether b starts with an SSLRequest,
// GSSENCRequest or protocol 3 StartupMessage.
func LooksLikeStartup(b []byte) bool {
	if len(b) < PeekLen {
		return false
	}
	length := binary.BigEndian.Uint32(b)
	switch binary.BigEndian.Uint32(b[4:]) {
	case SSLRequestCode, GSSENCRequestCode:
		return length == minStartupLen
	case ProtocolVersion3:
		return length > minStartupLen && length <= MaxStartupLen
	}
	return false
}
