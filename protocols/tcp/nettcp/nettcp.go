// Package nettcp parses .NET Message Framing (MS-NMF) records, the framing
// used by WCF NetTcpBinding (net.tcp://), and builds the server records the
// honeypot answers with. Record layout follows [MS-NMF] section 2.2.3.
package nettcp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Record types ([MS-NMF] 2.2.3).
const (
	RecordVersion            byte = 0x00
	RecordMode               byte = 0x01
	RecordVia                byte = 0x02
	RecordKnownEncoding      byte = 0x03
	RecordExtensibleEncoding byte = 0x04
	RecordUnsizedEnvelope    byte = 0x05
	RecordSizedEnvelope      byte = 0x06
	RecordEnd                byte = 0x07
	RecordFault              byte = 0x08
	RecordUpgradeRequest     byte = 0x09
	RecordUpgradeResponse    byte = 0x0A
	RecordPreambleAck        byte = 0x0B
	RecordPreambleEnd        byte = 0x0C
)

var recordNames = map[byte]string{
	RecordVersion:            "Version",
	RecordMode:               "Mode",
	RecordVia:                "Via",
	RecordKnownEncoding:      "KnownEncoding",
	RecordExtensibleEncoding: "ExtensibleEncoding",
	RecordUnsizedEnvelope:    "UnsizedEnvelope",
	RecordSizedEnvelope:      "SizedEnvelope",
	RecordEnd:                "End",
	RecordFault:              "Fault",
	RecordUpgradeRequest:     "UpgradeRequest",
	RecordUpgradeResponse:    "UpgradeResponse",
	RecordPreambleAck:        "PreambleAck",
	RecordPreambleEnd:        "PreambleEnd",
}

var modeNames = map[byte]string{
	1: "singleton-unsized",
	2: "duplex",
	3: "simplex",
	4: "singleton-sized",
}

// knownEncodings maps the Known Encoding record value to its content type
// ([MS-NMF] 2.2.3.4.1).
var knownEncodings = map[byte]string{
	0x00: "text/xml; charset=utf-8",
	0x01: "text/xml; charset=utf-16",
	0x02: "text/xml; charset=unicodeFFFE",
	0x03: "application/soap+xml; charset=utf-8",
	0x04: "application/soap+xml; charset=utf-16",
	0x05: "application/soap+xml; charset=unicodeFFFE",
	0x06: "multipart/related",
	0x07: "application/soap+msbin1",
	0x08: "application/soap+msbinsession1",
}

// Fault strings ([MS-NMF] 2.2.3.8).
const faultPrefix = "http://schemas.microsoft.com/ws/2006/05/framing/faults/"

const (
	FaultUnsupportedVersion = "UnsupportedVersion"
	FaultUnsupportedMode    = "UnsupportedMode"
	FaultContentTypeInvalid = "ContentTypeInvalid"
	FaultUpgradeInvalid     = "UpgradeInvalid"
)

var (
	// ErrUnknownRecord is returned for a record type byte MS-NMF does not define.
	ErrUnknownRecord = errors.New("nettcp: unknown record type")
	// ErrTooLarge is returned when a record body exceeds the caller's cap. The
	// returned Record holds the bytes read up to the cap and Truncated is set.
	ErrTooLarge = errors.New("nettcp: record exceeds size cap")
	// ErrBadLength is returned for a record size that is not a valid MS-NMF
	// variable-length integer.
	ErrBadLength = errors.New("nettcp: invalid record size")
)

// Record is one parsed MS-NMF record.
type Record struct {
	Type        byte
	Name        string
	Version     string // Version record: "major.minor"
	Mode        string // Mode record
	Via         string // Via record URI
	ContentType string // Known/Extensible Encoding, Upgrade Request
	Fault       string // Fault record string
	Body        []byte // envelope bytes (Sized/Unsized Envelope)
	Raw         []byte // record as seen on the wire
	Truncated   bool
}

// RecordName returns the MS-NMF name of a record type.
func RecordName(t byte) string {
	if n, ok := recordNames[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", t)
}

// ModeName returns the name of a Mode record value.
func ModeName(m byte) string {
	if n, ok := modeNames[m]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", m)
}

// readSize reads an MS-NMF variable-length integer (at most 5 bytes, 31 bits).
func readSize(r *bufio.Reader, raw *[]byte) (int, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		*raw = append(*raw, b)
		v |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if v > 0x7fffffff {
				return 0, ErrBadLength
			}
			return int(v), nil
		}
	}
	return 0, ErrBadLength
}

// EncodeSize encodes n as an MS-NMF variable-length integer.
func EncodeSize(n int) []byte {
	var out []byte
	v := uint32(n)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// readBody reads a size-prefixed body capped at max bytes.
func readBody(r *bufio.Reader, raw *[]byte, max int) ([]byte, bool, error) {
	n, err := readSize(r, raw)
	if err != nil {
		return nil, false, err
	}
	truncated := false
	want := n
	if want > max {
		want = max
		truncated = true
	}
	body := make([]byte, want)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, false, err
	}
	*raw = append(*raw, body...)
	if truncated {
		return body, true, ErrTooLarge
	}
	return body, false, nil
}

// ReadRecord reads one MS-NMF record from r. Strings (Via, content type,
// fault) and envelope bodies are capped at max bytes; an oversize record is
// returned with Truncated set together with ErrTooLarge.
func ReadRecord(r *bufio.Reader, max int) (Record, error) {
	t, err := r.ReadByte()
	if err != nil {
		return Record{}, err
	}
	rec := Record{Type: t, Name: RecordName(t), Raw: []byte{t}}
	switch t {
	case RecordVersion:
		var v [2]byte
		if _, err := io.ReadFull(r, v[:]); err != nil {
			return rec, err
		}
		rec.Raw = append(rec.Raw, v[:]...)
		rec.Version = fmt.Sprintf("%d.%d", v[0], v[1])
	case RecordMode:
		m, err := r.ReadByte()
		if err != nil {
			return rec, err
		}
		rec.Raw = append(rec.Raw, m)
		rec.Mode = ModeName(m)
	case RecordKnownEncoding:
		e, err := r.ReadByte()
		if err != nil {
			return rec, err
		}
		rec.Raw = append(rec.Raw, e)
		if ct, ok := knownEncodings[e]; ok {
			rec.ContentType = ct
		} else {
			rec.ContentType = fmt.Sprintf("0x%02x", e)
		}
	case RecordVia, RecordExtensibleEncoding, RecordFault, RecordUpgradeRequest:
		body, trunc, err := readBody(r, &rec.Raw, max)
		rec.Truncated = trunc
		switch t {
		case RecordVia:
			rec.Via = string(body)
		case RecordFault:
			rec.Fault = string(body)
		default:
			rec.ContentType = string(body)
		}
		if err != nil {
			return rec, err
		}
	case RecordSizedEnvelope:
		body, trunc, err := readBody(r, &rec.Raw, max)
		rec.Body, rec.Truncated = body, trunc
		if err != nil {
			return rec, err
		}
	case RecordUnsizedEnvelope:
		// Data chunks (size + bytes) terminated by a zero-length chunk.
		for {
			body, trunc, err := readBody(r, &rec.Raw, max-len(rec.Body))
			rec.Body = append(rec.Body, body...)
			if err != nil {
				rec.Truncated = trunc
				return rec, err
			}
			if len(body) == 0 {
				break
			}
		}
	case RecordEnd, RecordUpgradeResponse, RecordPreambleAck, RecordPreambleEnd:
	default:
		return rec, ErrUnknownRecord
	}
	return rec, nil
}

// FaultRecord builds a Fault record carrying the named framing fault.
func FaultRecord(name string) []byte {
	s := faultPrefix + name
	out := []byte{RecordFault}
	out = append(out, EncodeSize(len(s))...)
	return append(out, s...)
}

// FaultName strips the framing fault namespace from a fault string.
func FaultName(s string) string {
	if len(s) > len(faultPrefix) && s[:len(faultPrefix)] == faultPrefix {
		return s[len(faultPrefix):]
	}
	return s
}

// Reply is the server's answer to one client record. Close tells the caller
// to end the session after writing Data (if any).
type Reply struct {
	Data  []byte
	Close bool
}

// Respond returns the minimal server answer to a client record: Preamble Ack
// after Preamble End, End for End, and a framing Fault (then close) for an
// unsupported version, mode, encoding or any upgrade (no SSPI/TLS upgrade is
// emulated). Envelopes get no reply.
func Respond(rec Record) Reply {
	switch rec.Type {
	case RecordVersion:
		if len(rec.Raw) < 2 || rec.Raw[1] != 1 {
			return Reply{Data: FaultRecord(FaultUnsupportedVersion), Close: true}
		}
	case RecordMode:
		if len(rec.Raw) < 2 || modeNames[rec.Raw[1]] == "" {
			return Reply{Data: FaultRecord(FaultUnsupportedMode), Close: true}
		}
	case RecordKnownEncoding:
		if len(rec.Raw) < 2 || knownEncodings[rec.Raw[1]] == "" {
			return Reply{Data: FaultRecord(FaultContentTypeInvalid), Close: true}
		}
	case RecordUpgradeRequest:
		return Reply{Data: FaultRecord(FaultUpgradeInvalid), Close: true}
	case RecordPreambleEnd:
		return Reply{Data: []byte{RecordPreambleAck}}
	case RecordEnd:
		return Reply{Data: []byte{RecordEnd}, Close: true}
	case RecordFault, RecordPreambleAck, RecordUpgradeResponse:
		// Server-only records sent by a client: drop the session.
		return Reply{Close: true}
	}
	return Reply{}
}

// Parse decodes a server record built by this package for logging.
func Parse(data []byte) Record {
	rec, _ := ReadRecord(bufio.NewReader(bytes.NewReader(data)), len(data))
	return rec
}
