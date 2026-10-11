// Package ident parses Identification Protocol (RFC 1413) queries and builds
// the error replies an identd sends when it has no matching connection.
package ident

import (
	"regexp"
	"strconv"
)

// MaxLine caps a query line. A real query is two ports and a comma; the RFC
// lets the server drop anything longer than 1000 bytes, but scanners never
// come close.
const MaxLine = 128

// Error tokens from RFC 1413 §5.
const (
	ErrNoUser      = "NO-USER"
	ErrInvalidPort = "INVALID-PORT"
)

var queryRe = regexp.MustCompile(`^\s*(\d{1,5})\s*,\s*(\d{1,5})\s*$`)

// Query is one "<port-on-server>, <port-on-client>" request.
type Query struct {
	ServerPort int
	ClientPort int
}

// Valid reports whether both ports are in 1-65535.
func (q Query) Valid() bool {
	return q.ServerPort >= 1 && q.ServerPort <= 65535 && q.ClientPort >= 1 && q.ClientPort <= 65535
}

// ParseQuery parses one query line (trailing CR/LF allowed). ok is false when
// the line is not a port pair at all.
func ParseQuery(line []byte) (q Query, ok bool) {
	m := queryRe.FindSubmatch(line)
	if m == nil {
		return Query{}, false
	}
	// \d{1,5} cannot overflow an int.
	q.ServerPort, _ = strconv.Atoi(string(m[1]))
	q.ClientPort, _ = strconv.Atoi(string(m[2]))
	return q, true
}

// Error returns the RFC 1413 error token for a query: INVALID-PORT for ports
// out of range, otherwise NO-USER (no such connection, as identd answers for
// a pair it does not own).
func (q Query) Error() string {
	if !q.Valid() {
		return ErrInvalidPort
	}
	return ErrNoUser
}

// BuildReply builds "<server>, <client> : ERROR : <token>\r\n". Only the
// parsed port numbers are echoed, never the client's raw bytes.
func BuildReply(q Query) []byte {
	b := make([]byte, 0, 40)
	b = strconv.AppendInt(b, int64(q.ServerPort), 10)
	b = append(b, ", "...)
	b = strconv.AppendInt(b, int64(q.ClientPort), 10)
	b = append(b, " : ERROR : "...)
	b = append(b, q.Error()...)
	return append(b, "\r\n"...)
}
