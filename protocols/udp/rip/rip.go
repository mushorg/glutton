// Package rip parses RIPv1 (RFC 1058) and RIPv2 (RFC 2453) datagrams and
// builds the minimal responses the rip handler sends.
package rip

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	HeaderSize = 4
	EntrySize  = 20
	MaxEntries = 25

	CommandRequest  = 1
	CommandResponse = 2

	AFIUnspec = 0
	AFIInet   = 2
	AFIAuth   = 0xffff

	// Infinity is the unreachable metric; a request with one AFI 0 entry at
	// this metric asks for the whole routing table.
	Infinity = 16

	AuthSimple  = 2 // RFC 2453 §4.1: 16-byte plaintext password
	AuthKeyed   = 3 // RFC 2082 / RFC 4822 keyed message digest
	authTrailer = 1 // AFI 0xffff, type 1: the digest trailer
)

var (
	ErrShort      = errors.New("rip: datagram shorter than header")
	ErrBadLength  = errors.New("rip: entries are not a multiple of 20 bytes")
	ErrNoEntries  = errors.New("rip: no route entries")
	ErrBadVersion = errors.New("rip: unsupported version")
	ErrTooMany    = errors.New("rip: more than 25 route entries")
)

// Entry is one route entry. Mask, NextHop and RouteTag are only meaningful in
// RIPv2; RIPv1 requires those bytes to be zero.
type Entry struct {
	AFI      uint16
	RouteTag uint16
	Address  net.IP
	Mask     net.IP
	NextHop  net.IP
	Metric   uint32
}

// Auth is the RIPv2 authentication entry (always the first entry).
type Auth struct {
	Type uint16
	// Password is the raw 16-byte simple password (type 2).
	Password []byte
	// Keyed digest fields (type 3).
	PacketLen uint16
	KeyID     uint8
	DataLen   uint8
	Sequence  uint32
	// Digest is the trailer after the AFI/type of an AFI 0xffff type 1 entry.
	Digest []byte
}

// Packet is a parsed RIP datagram.
type Packet struct {
	Command uint8
	Version uint8
	Zero    uint16
	Entries []Entry
	Auth    *Auth
}

// Parse decodes a RIP datagram. It returns a Packet whenever the header was
// readable, together with an error if the rest is malformed.
func Parse(b []byte) (*Packet, error) {
	if len(b) < HeaderSize {
		return nil, ErrShort
	}
	p := &Packet{Command: b[0], Version: b[1], Zero: binary.BigEndian.Uint16(b[2:4])}
	if p.Version != 1 && p.Version != 2 {
		return p, ErrBadVersion
	}
	for off := HeaderSize; off < len(b); off += EntrySize {
		if len(b)-off < 4 {
			return p, ErrBadLength
		}
		afi := binary.BigEndian.Uint16(b[off:])
		if p.Version == 2 && afi == AFIAuth {
			typ := binary.BigEndian.Uint16(b[off+2:])
			if typ == authTrailer && p.Auth != nil {
				// The digest runs to the end of the datagram (16 bytes for
				// MD5, longer for HMAC-SHA).
				p.Auth.Digest = append([]byte(nil), b[off+4:]...)
				break
			}
			if len(b)-off < EntrySize {
				return p, ErrBadLength
			}
			if p.Auth == nil && len(p.Entries) == 0 {
				p.Auth = parseAuth(typ, b[off+4:off+EntrySize])
				continue
			}
		}
		if len(b)-off < EntrySize {
			return p, ErrBadLength
		}
		e := b[off : off+EntrySize]
		p.Entries = append(p.Entries, Entry{
			AFI:      afi,
			RouteTag: binary.BigEndian.Uint16(e[2:4]),
			Address:  net.IP(append([]byte(nil), e[4:8]...)),
			Mask:     net.IP(append([]byte(nil), e[8:12]...)),
			NextHop:  net.IP(append([]byte(nil), e[12:16]...)),
			Metric:   binary.BigEndian.Uint32(e[16:20]),
		})
	}
	if len(p.Entries) == 0 && p.Auth == nil {
		return p, ErrNoEntries
	}
	if len(p.Entries) > MaxEntries {
		return p, ErrTooMany
	}
	return p, nil
}

func parseAuth(typ uint16, body []byte) *Auth {
	a := &Auth{Type: typ}
	switch typ {
	case AuthSimple:
		a.Password = append([]byte(nil), body...)
	case AuthKeyed:
		a.PacketLen = binary.BigEndian.Uint16(body[0:2])
		a.KeyID = body[2]
		a.DataLen = body[3]
		a.Sequence = binary.BigEndian.Uint32(body[4:8])
	}
	return a
}

// LooksLikeRIP is the strict check the generic udp handler uses to reroute
// datagrams on arbitrary ports.
func LooksLikeRIP(b []byte) bool {
	if len(b) < HeaderSize+EntrySize || (len(b)-HeaderSize)%EntrySize != 0 {
		return false
	}
	if n := (len(b) - HeaderSize) / EntrySize; n > MaxEntries {
		return false
	}
	if b[0] != CommandRequest && b[0] != CommandResponse {
		return false
	}
	if b[1] != 1 && b[1] != 2 || b[2] != 0 || b[3] != 0 {
		return false
	}
	for off := HeaderSize; off < len(b); off += EntrySize {
		e := b[off : off+EntrySize]
		afi := binary.BigEndian.Uint16(e)
		if b[1] == 2 && afi == AFIAuth {
			continue
		}
		if afi != AFIUnspec && afi != AFIInet {
			return false
		}
		if b[1] == 1 && (e[2] != 0 || e[3] != 0 || !allZero(e[8:16])) {
			return false
		}
		if m := binary.BigEndian.Uint32(e[16:20]); m < 1 || m > Infinity {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// WholeTable reports whether p is a request for the entire routing table:
// exactly one entry with AFI 0 and metric 16.
func (p *Packet) WholeTable() bool {
	return p.Command == CommandRequest && len(p.Entries) == 1 &&
		p.Entries[0].AFI == AFIUnspec && p.Entries[0].Metric == Infinity
}

// CommandName names the command byte.
func CommandName(c uint8) string {
	switch c {
	case CommandRequest:
		return "request"
	case CommandResponse:
		return "response"
	case 3:
		return "traceon"
	case 4:
		return "traceoff"
	case 5:
		return "poll"
	}
	return "unknown"
}

// AuthTypeName names an authentication type.
func AuthTypeName(t uint16) string {
	switch t {
	case AuthSimple:
		return "simple"
	case AuthKeyed:
		return "keyed"
	}
	return fmt.Sprintf("0x%04x", t)
}

// RouteFor derives the sensor's one advertised route from seed: a stable
// 192.168.x.0/24 (classful, so RIPv1 receivers read the same prefix) at
// metric 1, as for a directly connected network.
func RouteFor(seed []byte) Entry {
	sum := sha256.Sum256(append([]byte("rip:"), seed...))
	return Entry{
		AFI:     AFIInet,
		Address: net.IPv4(192, 168, 1+sum[0]%254, 0).To4(),
		Mask:    net.IPv4(255, 255, 255, 0).To4(),
		NextHop: net.IPv4zero.To4(),
		Metric:  1,
	}
}

// BuildResponse encodes a Response (command 2). RIPv1 entries carry only the
// AFI, address and metric; the RIPv2 fields are zeroed.
func BuildResponse(version uint8, entries []Entry) []byte {
	b := make([]byte, HeaderSize+EntrySize*len(entries))
	b[0], b[1] = CommandResponse, version
	for i, e := range entries {
		o := b[HeaderSize+i*EntrySize:]
		binary.BigEndian.PutUint16(o[0:2], e.AFI)
		copy(o[4:8], e.Address.To4())
		if version >= 2 {
			binary.BigEndian.PutUint16(o[2:4], e.RouteTag)
			copy(o[8:12], e.Mask.To4())
			copy(o[12:16], e.NextHop.To4())
		}
		binary.BigEndian.PutUint32(o[16:20], e.Metric)
	}
	return b
}

// Answer builds the reply to a Request from a router that knows only route.
// A whole-table request gets route; a specific request gets each asked entry
// back with route's metric if it matches route's prefix, otherwise 16. The
// reply never has more route entries than the request, so it is never larger.
// It returns nil when p is not an answerable request.
func Answer(p *Packet, route Entry) []byte {
	if p == nil || p.Command != CommandRequest || len(p.Entries) == 0 {
		return nil
	}
	if p.WholeTable() {
		return BuildResponse(p.Version, []Entry{route})
	}
	out := make([]Entry, 0, len(p.Entries))
	for _, e := range p.Entries {
		r := Entry{AFI: e.AFI, RouteTag: e.RouteTag, Address: e.Address, Mask: e.Mask, NextHop: e.NextHop, Metric: Infinity}
		if e.AFI == AFIInet && e.Address.Equal(route.Address) {
			r.Metric = route.Metric
			if p.Version >= 2 {
				r.Mask = route.Mask
			}
		}
		out = append(out, r)
	}
	return BuildResponse(p.Version, out)
}
