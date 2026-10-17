// Package tftp parses TFTP (RFC 1350, options per RFC 2347) request packets
// and builds ERROR replies. It does no I/O.
package tftp

import (
	"bytes"
	"errors"
	"strings"
)

// Opcodes.
const (
	OpRRQ   uint16 = 1
	OpWRQ   uint16 = 2
	OpData  uint16 = 3
	OpAck   uint16 = 4
	OpError uint16 = 5
	OpOACK  uint16 = 6
)

// Error codes.
const (
	ErrFileNotFound    uint16 = 1
	ErrAccessViolation uint16 = 2
)

// MaxField caps the filename, mode and option strings kept from a request.
const MaxField = 255

var ErrMalformed = errors.New("malformed TFTP request")

// Option is one RFC 2347 option name/value pair.
type Option struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Request is a parsed RRQ or WRQ.
type Request struct {
	Opcode   uint16
	Filename string
	Mode     string
	Options  []Option
}

// OpcodeName returns "RRQ", "WRQ", ... or "unknown".
func OpcodeName(op uint16) string {
	switch op {
	case OpRRQ:
		return "RRQ"
	case OpWRQ:
		return "WRQ"
	case OpData:
		return "DATA"
	case OpAck:
		return "ACK"
	case OpError:
		return "ERROR"
	case OpOACK:
		return "OACK"
	}
	return "unknown"
}

func validMode(m string) bool {
	switch strings.ToLower(m) {
	case "netascii", "octet", "mail":
		return true
	}
	return false
}

// Parse decodes an RRQ/WRQ: opcode, NUL-terminated filename and mode, then
// optional NUL-terminated option name/value pairs.
func Parse(data []byte) (*Request, error) {
	if len(data) < 6 {
		return nil, ErrMalformed
	}
	op := uint16(data[0])<<8 | uint16(data[1])
	if op != OpRRQ && op != OpWRQ {
		return nil, ErrMalformed
	}
	rest := data[2:]
	if rest[len(rest)-1] != 0 {
		return nil, ErrMalformed
	}
	fields := bytes.Split(rest[:len(rest)-1], []byte{0})
	if len(fields) < 2 || len(fields)%2 != 0 || len(fields[0]) == 0 || !validMode(string(fields[1])) {
		return nil, ErrMalformed
	}
	req := &Request{Opcode: op, Filename: clip(fields[0]), Mode: strings.ToLower(clip(fields[1]))}
	for i := 2; i+1 < len(fields); i += 2 {
		req.Options = append(req.Options, Option{Name: clip(fields[i]), Value: clip(fields[i+1])})
	}
	return req, nil
}

func clip(b []byte) string {
	if len(b) > MaxField {
		b = b[:MaxField]
	}
	return string(b)
}

// LooksLikeTFTP reports whether data is a well-formed RRQ/WRQ.
func LooksLikeTFTP(data []byte) bool {
	_, err := Parse(data)
	return err == nil
}

// ErrorPacket builds an ERROR packet: opcode 5, code, message, NUL.
func ErrorPacket(code uint16, msg string) []byte {
	out := []byte{0, byte(OpError), byte(code >> 8), byte(code)}
	out = append(out, msg...)
	return append(out, 0)
}

// ErrorFitting builds an ERROR packet no larger than maxLen bytes by trimming
// the message, so a reply is never bigger than the request that caused it.
func ErrorFitting(code uint16, msg string, maxLen int) []byte {
	if room := maxLen - 5; room < len(msg) {
		msg = msg[:max(room, 0)]
	}
	return ErrorPacket(code, msg)
}
