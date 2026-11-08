// Package pcanywhere parses Symantec pcAnywhere UDP discovery queries
// (udp/5632) and builds their replies.
//
// The wire format follows the Metasploit auxiliary/scanner/pcanywhere/pcanywhere_udp
// scanner (BSD-3-Clause), recalled rather than checked against a live host:
// the client sends the two-byte name query "NQ" or status query "ST". A host
// answers "NQ" with "NR", a 24-byte host name and an 8-byte capability field,
// both padded with '_'. It answers "ST" with "ST" plus a status block whose
// third byte is 'C' (67) when the host is available and 0x0b when it is busy.
package pcanywhere

import (
	"bytes"
	"strings"
)

const (
	// NameQuery asks for the host name and capabilities.
	NameQuery = "NQ"
	// StatusQuery asks whether the host is available.
	StatusQuery = "ST"

	nameLen = 24
	capsLen = 8

	// StatusAvailable is the status byte of an idle host.
	StatusAvailable = 'C'
)

// Persona is the host a reply describes.
type Persona struct {
	Name string // host name, at most 24 bytes
	Caps string // capability field, at most 8 bytes
}

// DefaultPersona is an idle Windows workstation running pcAnywhere host.
var DefaultPersona = Persona{Name: "ACCT-PC01", Caps: "AHM_3___"}

// Command names a query datagram: "NQ", "ST", or "" for anything else.
// Trailing CR, LF or NUL bytes are tolerated.
func Command(data []byte) string {
	switch string(bytes.TrimRight(data, "\r\n\x00")) {
	case NameQuery:
		return NameQuery
	case StatusQuery:
		return StatusQuery
	}
	return ""
}

func pad(s string, n int) []byte {
	if len(s) > n {
		s = s[:n]
	}
	return []byte(s + strings.Repeat("_", n-len(s)))
}

// Reply returns the answer to cmd and its status label, or nil for an
// unknown command.
func Reply(cmd string, p Persona) ([]byte, string) {
	switch cmd {
	case NameQuery:
		out := append([]byte("NR"), pad(p.Name, nameLen)...)
		return append(out, pad(p.Caps, capsLen)...), "NR"
	case StatusQuery:
		return []byte{'S', 'T', 0x00, 0x00, StatusAvailable, 0x00}, "available"
	}
	return nil, ""
}
