// Package rtp parses the RTP media a SIP caller sends after a call is
// answered (RFC 3550), decodes RFC 4733 telephone-event DTMF, and lays G.711
// audio out by RTP timestamp so it can be saved as a WAV file. It does no I/O.
package rtp

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Static payload types (RFC 3551) the honeypot answers with.
const (
	PCMU = 0
	PCMA = 8
)

// SampleRate is the RTP clock and sample rate of G.711 and telephone-event.
const SampleRate = 8000

const headerLen = 12

var (
	ErrShort   = errors.New("rtp: packet too short")
	ErrVersion = errors.New("rtp: not version 2")
)

// Header is the fixed RTP header plus the CSRC count.
type Header struct {
	Padding     bool
	Extension   bool
	Marker      bool
	PayloadType uint8
	Seq         uint16
	Timestamp   uint32
	SSRC        uint32
	CSRCCount   int
}

// Parse returns the header and payload of an RTP packet, skipping CSRCs, a
// header extension and padding. The payload aliases data.
func Parse(data []byte) (Header, []byte, error) {
	if len(data) < headerLen {
		return Header{}, nil, ErrShort
	}
	if data[0]>>6 != 2 {
		return Header{}, nil, ErrVersion
	}
	h := Header{
		Padding:     data[0]&0x20 != 0,
		Extension:   data[0]&0x10 != 0,
		CSRCCount:   int(data[0] & 0x0f),
		Marker:      data[1]&0x80 != 0,
		PayloadType: data[1] & 0x7f,
		Seq:         binary.BigEndian.Uint16(data[2:4]),
		Timestamp:   binary.BigEndian.Uint32(data[4:8]),
		SSRC:        binary.BigEndian.Uint32(data[8:12]),
	}
	// payload types 72-76 are RTCP packet types sent to the RTP port (RFC 5761)
	if h.PayloadType >= 72 && h.PayloadType <= 76 {
		return Header{}, nil, ErrVersion
	}
	off := headerLen + 4*h.CSRCCount
	if len(data) < off {
		return Header{}, nil, ErrShort
	}
	if h.Extension {
		if len(data) < off+4 {
			return Header{}, nil, ErrShort
		}
		off += 4 + 4*int(binary.BigEndian.Uint16(data[off+2:off+4]))
		if len(data) < off {
			return Header{}, nil, ErrShort
		}
	}
	end := len(data)
	if h.Padding {
		pad := int(data[end-1])
		if pad == 0 || end-pad < off {
			return Header{}, nil, ErrShort
		}
		end -= pad
	}
	return h, data[off:end], nil
}

// Event is an RFC 4733 named telephone event.
type Event struct {
	Code     uint8
	End      bool
	Volume   uint8
	Duration uint16
}

// ParseEvent decodes a telephone-event payload.
func ParseEvent(payload []byte) (Event, error) {
	if len(payload) < 4 {
		return Event{}, ErrShort
	}
	return Event{
		Code:     payload[0],
		End:      payload[1]&0x80 != 0,
		Volume:   payload[1] & 0x3f,
		Duration: binary.BigEndian.Uint16(payload[2:4]),
	}, nil
}

// Digit returns the DTMF key of the event (0-9, *, #, A-D), or "" for other
// events such as flash.
func (e Event) Digit() string {
	const keys = "0123456789*#ABCD"
	if int(e.Code) < len(keys) {
		return keys[e.Code : e.Code+1]
	}
	return ""
}

// Media is the audio section of an SDP body.
type Media struct {
	IP    net.IP           // connection address (media-level c= wins over session-level)
	Port  int              // m=audio port
	Names map[uint8]string // payload type -> encoding name (rtpmap, plus static PCMU/PCMA)
}

// DTMF returns the telephone-event payload type, or -1.
func (m Media) DTMF() int {
	for pt, name := range m.Names {
		if strings.EqualFold(name, "telephone-event") {
			return int(pt)
		}
	}
	return -1
}

// ParseSDPAudio returns the first audio section of an SDP body.
func ParseSDPAudio(sdp string) (Media, bool) {
	m := Media{Names: map[uint8]string{PCMU: "PCMU", PCMA: "PCMA"}}
	var session net.IP
	inAudio, found := false, false
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "m="):
			if found {
				inAudio = false
				continue
			}
			fields := strings.Fields(line[2:])
			if len(fields) >= 2 && fields[0] == "audio" {
				if port, err := strconv.Atoi(fields[1]); err == nil && port > 0 && port < 65536 {
					m.Port, inAudio, found = port, true, true
				}
			}
		case strings.HasPrefix(line, "c="):
			fields := strings.Fields(line[2:])
			if len(fields) < 3 {
				continue
			}
			ip := net.ParseIP(fields[2])
			if inAudio {
				m.IP = ip
			} else if !found {
				session = ip
			}
		case inAudio && strings.HasPrefix(line, "a=rtpmap:"):
			pt, enc, ok := strings.Cut(line[len("a=rtpmap:"):], " ")
			n, err := strconv.Atoi(pt)
			if !ok || err != nil || n < 0 || n > 127 {
				continue
			}
			name, _, _ := strings.Cut(enc, "/")
			m.Names[uint8(n)] = name
		}
	}
	if m.IP == nil {
		m.IP = session
	}
	return m, found
}
