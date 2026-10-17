// Package steam parses Steam In-Home Streaming / Remote Play discovery
// datagrams (udp/27036). It only decodes requests; it never builds the
// Status reply a real client sends, because that reply (version, hostname,
// OS, timestamp) is larger than the probe and would turn the sensor into a
// UDP amplifier.
package steam

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// Magic starts every Remote Play broadcast datagram.
var Magic = []byte{0xff, 0xff, 0xff, 0xff, 0x21, 0x4c, 0x5f, 0xa0}

// MsgDiscovery is msg_type 0 of CMsgRemoteClientBroadcastHeader
// (ERemoteClientBroadcastMsg in Valve's steammessages_remoteplay.proto).
const MsgDiscovery uint64 = 0

var msgNames = map[uint64]string{
	0:  "discovery",
	1:  "status",
	2:  "offline",
	3:  "device_authorization_request",
	4:  "device_authorization_response",
	5:  "device_streaming_request",
	6:  "device_streaming_response",
	7:  "device_proof_request",
	8:  "device_proof_response",
	9:  "device_authorization_cancel_request",
	10: "device_streaming_cancel_request",
}

// Name returns the command name for a msg_type, or UNKNOWN.
func Name(t uint64) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return "UNKNOWN"
}

// Message is the decoded header and, for discovery, the body sequence number.
type Message struct {
	ClientID    uint64
	MsgType     uint64
	HasHeader   bool // header decoded; MsgType is meaningful
	SequenceNum uint32
}

// ClientIDString renders the 64-bit client ID in decimal, which survives JSON
// consumers that read numbers as float64.
func (m Message) ClientIDString() string {
	if m.ClientID == 0 {
		return ""
	}
	return strconv.FormatUint(m.ClientID, 10)
}

// LooksLikeSteam reports whether data starts with the Remote Play magic.
func LooksLikeSteam(data []byte) bool {
	return len(data) >= len(Magic) && bytes.HasPrefix(data, Magic)
}

// Parse decodes magic | u32le header_len | header | u32le body_len | body.
// On error it returns whatever was decoded before the failure.
func Parse(data []byte) (Message, error) {
	var m Message
	if !LooksLikeSteam(data) {
		return m, errors.New("missing Steam discovery magic")
	}
	off := len(Magic)
	if len(data) < off+4 {
		return m, errors.New("truncated header length")
	}
	hlen := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if hlen < 0 || hlen > len(data)-off {
		return m, fmt.Errorf("header length %d exceeds datagram", hlen)
	}
	header := data[off : off+hlen]
	off += hlen
	if err := walk(header, func(field, v uint64) {
		switch field {
		case 1:
			m.ClientID = v
		case 2:
			m.MsgType = v
		}
	}); err != nil {
		return m, fmt.Errorf("header: %w", err)
	}
	m.HasHeader = true

	if len(data) < off+4 {
		return m, errors.New("truncated body length")
	}
	blen := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if blen < 0 || blen > len(data)-off {
		return m, fmt.Errorf("body length %d exceeds datagram", blen)
	}
	if m.MsgType == MsgDiscovery {
		if err := walk(data[off:off+blen], func(field, v uint64) {
			if field == 1 {
				m.SequenceNum = uint32(v)
			}
		}); err != nil {
			return m, fmt.Errorf("body: %w", err)
		}
	}
	return m, nil
}

// walk iterates protobuf fields and calls fn with the field number and value
// of each varint field. Other wire types are skipped.
func walk(b []byte, fn func(field, v uint64)) error {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return errors.New("bad tag varint")
		}
		b = b[n:]
		field, wire := tag>>3, tag&7
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errors.New("bad varint")
			}
			b = b[n:]
			fn(field, v)
		case 1:
			if len(b) < 8 {
				return errors.New("truncated fixed64")
			}
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return errors.New("bad length-delimited field")
			}
			b = b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return errors.New("truncated fixed32")
			}
			b = b[4:]
		default:
			return fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return nil
}
