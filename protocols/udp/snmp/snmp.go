// Package snmp parses SNMPv1/v2c messages (RFC 3416, BER) and builds the
// replies of a small read-only embedded agent. It does no I/O.
package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER tags.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30
	tagTimeTicks   = 0x43

	// Exception values (v2c varbind values).
	tagNoSuchObject = 0x80
	tagEndOfMibView = 0x82
)

// PDU tags.
const (
	PDUGet       = 0xa0
	PDUGetNext   = 0xa1
	PDUResponse  = 0xa2
	PDUSet       = 0xa3
	PDUTrapV1    = 0xa4
	PDUGetBulk   = 0xa5
	PDUInform    = 0xa6
	PDUTrapV2    = 0xa7
	pduTagFirst  = PDUGet
	pduTagLast   = PDUTrapV2
	maxArcs      = 128
	maxVarbinds  = 64
	maxBulkRound = 64
)

// Versions as carried on the wire.
const (
	Version1  = 0
	Version2c = 1
	Version3  = 3
)

// Error statuses (RFC 3416).
const (
	ErrNoError    = 0
	ErrTooBig     = 1
	ErrNoSuchName = 2
	ErrNoAccess   = 6
)

// Community is the only community the agent answers.
const Community = "public"

// Message is a parsed SNMPv1/v2c message. Version 3 is recognized but not
// decoded further.
type Message struct {
	Version   int
	Community string
	PDUType   byte
	RequestID int64
	// ErrorStatus/ErrorIndex for most PDUs; for GetBulk these are the
	// non-repeaters and max-repetitions values.
	NonRepeaters   int64
	MaxRepetitions int64
	OIDs           []OID
}

// OID is a decoded object identifier.
type OID []uint32

func (o OID) String() string {
	parts := make([]string, len(o))
	for i, a := range o {
		parts[i] = strconv.FormatUint(uint64(a), 10)
	}
	return strings.Join(parts, ".")
}

// compare orders OIDs lexicographically.
func (o OID) compare(p OID) int {
	for i := 0; i < len(o) && i < len(p); i++ {
		if o[i] != p[i] {
			if o[i] < p[i] {
				return -1
			}
			return 1
		}
	}
	return len(o) - len(p)
}

// VersionName returns v1, v2c or v3.
func VersionName(v int) string {
	switch v {
	case Version1:
		return "v1"
	case Version2c:
		return "v2c"
	case Version3:
		return "v3"
	}
	return "v" + strconv.Itoa(v)
}

// PDUName names a PDU tag.
func PDUName(t byte) string {
	switch t {
	case PDUGet:
		return "GetRequest"
	case PDUGetNext:
		return "GetNextRequest"
	case PDUResponse:
		return "GetResponse"
	case PDUSet:
		return "SetRequest"
	case PDUTrapV1:
		return "Trap"
	case PDUGetBulk:
		return "GetBulkRequest"
	case PDUInform:
		return "InformRequest"
	case PDUTrapV2:
		return "SNMPv2-Trap"
	}
	return "UNKNOWN"
}

var errBER = errors.New("snmp: malformed BER")

// readTLV reads one single-byte-tag TLV and returns the rest of the input.
func readTLV(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	n := int(b[1])
	off := 2
	switch {
	case n < 0x80:
	case n == 0x81 && len(b) >= 3:
		n, off = int(b[2]), 3
	case n == 0x82 && len(b) >= 4:
		n, off = int(b[2])<<8|int(b[3]), 4
	default:
		return 0, nil, nil, errBER
	}
	if n > len(b)-off {
		return 0, nil, nil, errBER
	}
	return tag, b[off : off+n], b[off+n:], nil
}

func readInt(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, errBER
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

func expect(b []byte, want byte) (val, rest []byte, err error) {
	tag, val, rest, err := readTLV(b)
	if err != nil {
		return nil, nil, err
	}
	if tag != want {
		return nil, nil, fmt.Errorf("snmp: tag %#x, want %#x", tag, want)
	}
	return val, rest, nil
}

// LooksLikeSNMP reports whether data is a well-formed SNMP message: an outer
// SEQUENCE spanning the datagram, version 0/1/3, and for v1/v2c a community
// string followed by a PDU tag. Version 3 is accepted when the next element
// is the msgGlobalData SEQUENCE.
func LooksLikeSNMP(data []byte) bool {
	tag, body, rest, err := readTLV(data)
	if err != nil || tag != tagSequence || len(rest) != 0 {
		return false
	}
	verBytes, body, err := expect(body, tagInteger)
	if err != nil {
		return false
	}
	ver, err := readInt(verBytes)
	if err != nil {
		return false
	}
	switch ver {
	case Version1, Version2c:
		_, body, err = expect(body, tagOctetString)
		if err != nil || len(body) == 0 {
			return false
		}
		return body[0] >= pduTagFirst && body[0] <= pduTagLast
	case Version3:
		return len(body) > 0 && body[0] == tagSequence
	}
	return false
}

// Parse decodes a v1/v2c message. For v3 it returns only Version set.
func Parse(data []byte) (*Message, error) {
	body, rest, err := expect(data, tagSequence)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBER
	}
	verBytes, body, err := expect(body, tagInteger)
	if err != nil {
		return nil, err
	}
	ver, err := readInt(verBytes)
	if err != nil {
		return nil, err
	}
	m := &Message{Version: int(ver)}
	if ver == Version3 {
		return m, nil
	}
	if ver != Version1 && ver != Version2c {
		return nil, fmt.Errorf("snmp: unsupported version %d", ver)
	}
	comm, body, err := expect(body, tagOctetString)
	if err != nil {
		return nil, err
	}
	m.Community = string(comm)

	pduTag, pdu, _, err := readTLV(body)
	if err != nil {
		return nil, err
	}
	if pduTag < pduTagFirst || pduTag > pduTagLast {
		return nil, fmt.Errorf("snmp: PDU tag %#x", pduTag)
	}
	m.PDUType = pduTag
	if pduTag == PDUTrapV1 {
		// v1 Trap has a different layout; the PDU tag is enough.
		return m, nil
	}

	reqID, pdu, err := intField(pdu)
	if err != nil {
		return nil, err
	}
	m.RequestID = reqID
	if m.NonRepeaters, pdu, err = intField(pdu); err != nil {
		return nil, err
	}
	if m.MaxRepetitions, pdu, err = intField(pdu); err != nil {
		return nil, err
	}
	vbl, _, err := expect(pdu, tagSequence)
	if err != nil {
		return nil, err
	}
	for len(vbl) > 0 && len(m.OIDs) < maxVarbinds {
		var vb []byte
		vb, vbl, err = expect(vbl, tagSequence)
		if err != nil {
			return nil, err
		}
		oidBytes, _, err := expect(vb, tagOID)
		if err != nil {
			return nil, err
		}
		oid, err := decodeOID(oidBytes)
		if err != nil {
			return nil, err
		}
		m.OIDs = append(m.OIDs, oid)
	}
	return m, nil
}

func intField(b []byte) (int64, []byte, error) {
	v, rest, err := expect(b, tagInteger)
	if err != nil {
		return 0, nil, err
	}
	n, err := readInt(v)
	return n, rest, err
}

func decodeOID(b []byte) (OID, error) {
	if len(b) == 0 {
		return nil, errBER
	}
	var arcs []uint32
	var cur uint64
	for i, c := range b {
		cur = cur<<7 | uint64(c&0x7f)
		if cur > 0xffffffff {
			return nil, errBER
		}
		if c&0x80 != 0 {
			if i == len(b)-1 {
				return nil, errBER
			}
			continue
		}
		if len(arcs) == 0 {
			switch {
			case cur < 40:
				arcs = append(arcs, 0, uint32(cur))
			case cur < 80:
				arcs = append(arcs, 1, uint32(cur-40))
			default:
				arcs = append(arcs, 2, uint32(cur-80))
			}
		} else {
			arcs = append(arcs, uint32(cur))
		}
		cur = 0
		if len(arcs) > maxArcs {
			return nil, errBER
		}
	}
	return arcs, nil
}

// --- encoding ---

func encLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+3+len(content))
	out = append(out, tag)
	out = append(out, encLen(len(content))...)
	return append(out, content...)
}

func encInt(tag byte, v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return tlv(tag, b)
}

func encOID(o OID) []byte {
	var b []byte
	put := func(v uint32) {
		var tmp [5]byte
		i := len(tmp)
		i--
		tmp[i] = byte(v & 0x7f)
		for v >>= 7; v > 0; v >>= 7 {
			i--
			tmp[i] = byte(v&0x7f) | 0x80
		}
		b = append(b, tmp[i:]...)
	}
	if len(o) >= 2 {
		put(o[0]*40 + o[1])
		for _, a := range o[2:] {
			put(a)
		}
	}
	return tlv(tagOID, b)
}

func varbind(o OID, value []byte) []byte {
	return tlv(tagSequence, append(encOID(o), value...))
}

func encodeMessage(version int, community string, reqID int64, errStatus, errIndex int, varbinds [][]byte) []byte {
	var vbl []byte
	for _, vb := range varbinds {
		vbl = append(vbl, vb...)
	}
	pdu := encInt(tagInteger, reqID)
	pdu = append(pdu, encInt(tagInteger, int64(errStatus))...)
	pdu = append(pdu, encInt(tagInteger, int64(errIndex))...)
	pdu = append(pdu, tlv(tagSequence, vbl)...)
	msg := encInt(tagInteger, int64(version))
	msg = append(msg, tlv(tagOctetString, []byte(community))...)
	msg = append(msg, tlv(PDUResponse, pdu)...)
	return tlv(tagSequence, msg)
}

var (
	nullValue         = []byte{tagNull, 0}
	noSuchObjectValue = []byte{tagNoSuchObject, 0}
	endOfMibValue     = []byte{tagEndOfMibView, 0}
)
