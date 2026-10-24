// Package mssql parses Microsoft SQL Server TDS messages (MS-TDS) and builds
// the replies the mssql handler sends: the PRELOGIN response, an SSPI token
// carrying an NTLM CHALLENGE, the login-failed ERROR/DONE pair, and after an
// accepted login the LOGINACK and canned replies to SQL batches and RPCs.
package mssql

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TDS packet types (MS-TDS 2.2.3.1.1).
const (
	TypeSQLBatch    = 0x01
	TypePreTDS7     = 0x02
	TypeRPC         = 0x03
	TypeTabular     = 0x04
	TypeAttention   = 0x06
	TypeBulkLoad    = 0x07
	TypeFedAuth     = 0x08
	TypeTransaction = 0x0e
	TypeLogin7      = 0x10
	TypeSSPI        = 0x11
	TypePrelogin    = 0x12
)

// HeaderLen is the size of the TDS packet header.
const HeaderLen = 8

// statusEOM marks the last packet of a message.
const statusEOM = 0x01

// MaxPacketLen is the largest packet size a server negotiates (32767, rounded
// up to the 32 KiB clients use as the upper bound).
const MaxPacketLen = 32768

// ErrBadHeader is returned for a packet header that cannot start a TDS packet.
var ErrBadHeader = errors.New("invalid TDS packet header")

var typeNames = map[byte]string{
	TypeSQLBatch:    "sql_batch",
	TypePreTDS7:     "pre_tds7_login",
	TypeRPC:         "rpc",
	TypeTabular:     "tabular_result",
	TypeAttention:   "attention",
	TypeBulkLoad:    "bulk_load",
	TypeFedAuth:     "fedauth_token",
	TypeTransaction: "transaction_manager",
	TypeLogin7:      "login7",
	TypeSSPI:        "sspi",
	TypePrelogin:    "prelogin",
}

// TypeName returns the command name for a packet type.
func TypeName(t byte) string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("type_0x%02x", t)
}

// Message is one TDS message, reassembled from its packets.
type Message struct {
	Type byte
	// Raw holds every packet as read, headers included.
	Raw []byte
	// Data is the concatenated packet payloads.
	Data []byte
	// Truncated is set when the message exceeded the read cap; Raw and Data
	// hold the packets read up to it.
	Truncated bool
}

// ReadMessage reads packets from r until the end-of-message packet. Once
// maxLen bytes have been read the message is returned with Truncated set and
// the rest is left unread. On an error Raw still holds the bytes read.
func ReadMessage(r io.Reader, maxLen int) (Message, error) {
	var msg Message
	for first := true; ; first = false {
		hdr := make([]byte, HeaderLen)
		if k, err := io.ReadFull(r, hdr); err != nil {
			msg.Raw = append(msg.Raw, hdr[:k]...)
			if !first && errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return msg, err
		}
		if first {
			msg.Type = hdr[0]
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < HeaderLen || n > MaxPacketLen {
			msg.Raw = append(msg.Raw, hdr...)
			return msg, fmt.Errorf("%w: length %d", ErrBadHeader, n)
		}
		if hdr[0] != msg.Type {
			msg.Raw = append(msg.Raw, hdr...)
			return msg, fmt.Errorf("%w: type 0x%02x inside a 0x%02x message", ErrBadHeader, hdr[0], msg.Type)
		}
		body := make([]byte, n-HeaderLen)
		if k, err := io.ReadFull(r, body); err != nil {
			msg.Raw = append(append(msg.Raw, hdr...), body[:k]...)
			return msg, err
		}
		msg.Raw = append(append(msg.Raw, hdr...), body...)
		msg.Data = append(msg.Data, body...)
		if hdr[1]&statusEOM != 0 {
			return msg, nil
		}
		if len(msg.Raw) >= maxLen {
			msg.Truncated = true
			return msg, nil
		}
	}
}

// LooksLikePrelogin reports whether b starts a PRELOGIN packet: type 0x12,
// a final packet, a sane length, and a first option token the client sends
// (VERSION).
func LooksLikePrelogin(b []byte) bool {
	if len(b) < HeaderLen+1 || b[0] != TypePrelogin || b[1] != statusEOM {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	return n > HeaderLen+5 && n <= MaxPacketLen && b[HeaderLen] == optVersion
}

// packet wraps data in a single tabular-result packet, as a server replies.
func packet(typ byte, data []byte) []byte {
	out := make([]byte, HeaderLen+len(data))
	out[0] = typ
	out[1] = statusEOM
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[6] = 1 // PacketID
	copy(out[HeaderLen:], data)
	return out
}
