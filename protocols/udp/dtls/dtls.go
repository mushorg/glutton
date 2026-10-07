// Package dtls parses DTLS ClientHello records and builds the stateless
// HelloVerifyRequest answer (RFC 6347 section 4.2.1). It does no I/O and does
// not implement the rest of the handshake.
package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	contentTypeHandshake = 22

	handshakeClientHello        = 1
	handshakeHelloVerifyRequest = 3

	// VersionDTLS10 and VersionDTLS12 are the wire versions (1's complement
	// of the TLS version, so DTLS 1.0 is 254.255 and DTLS 1.2 is 254.253).
	VersionDTLS10 uint16 = 0xfeff
	VersionDTLS12 uint16 = 0xfefd

	recordHeaderLen    = 13
	handshakeHeaderLen = 12
	// CookieLen is the length of the cookie Cookie returns.
	CookieLen = 16

	extServerName = 0
)

// ErrTruncated is returned when the datagram ends inside a field.
var ErrTruncated = errors.New("dtls: truncated")

// Extension is one ClientHello extension.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is a parsed epoch-0 ClientHello record.
type ClientHello struct {
	RecordVersion uint16
	Epoch         uint16
	Sequence      uint64 // 48-bit record sequence number
	MessageSeq    uint16
	ClientVersion uint16
	Random        []byte
	SessionID     []byte
	Cookie        []byte
	CipherSuites  []uint16
	Compression   []byte
	Extensions    []Extension
	ServerName    string // first host_name in the SNI extension
}

func validVersion(v uint16) bool { return v == VersionDTLS10 || v == VersionDTLS12 }

// LooksLikeDTLS reports whether data starts with an unfragmented epoch-0
// ClientHello handshake record whose length fits in the datagram. Used to
// reroute from the generic udp handler, so it is deliberately strict.
func LooksLikeDTLS(data []byte) bool {
	if len(data) < recordHeaderLen+handshakeHeaderLen ||
		data[0] != contentTypeHandshake ||
		!validVersion(binary.BigEndian.Uint16(data[1:3])) ||
		binary.BigEndian.Uint16(data[3:5]) != 0 {
		return false
	}
	recLen := int(binary.BigEndian.Uint16(data[11:13]))
	if recLen < handshakeHeaderLen || recordHeaderLen+recLen > len(data) {
		return false
	}
	hs := data[recordHeaderLen:]
	hsLen := u24(hs[1:4])
	return hs[0] == handshakeClientHello && hsLen+handshakeHeaderLen <= recLen &&
		u24(hs[6:9]) == 0 && u24(hs[9:12]) == hsLen
}

func u24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// ParseClientHello decodes the first record of data. When the record and
// handshake headers are readable the returned hello is non-nil even if an
// error is returned, with the fields parsed so far filled in.
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < recordHeaderLen {
		return nil, ErrTruncated
	}
	if data[0] != contentTypeHandshake {
		return nil, fmt.Errorf("dtls: content type %d is not handshake", data[0])
	}
	ch := &ClientHello{
		RecordVersion: binary.BigEndian.Uint16(data[1:3]),
		Epoch:         binary.BigEndian.Uint16(data[3:5]),
		Sequence:      uint64(data[5])<<40 | uint64(data[6])<<32 | uint64(binary.BigEndian.Uint32(data[7:11])),
	}
	if !validVersion(ch.RecordVersion) {
		return nil, fmt.Errorf("dtls: record version %#04x", ch.RecordVersion)
	}
	recLen := int(binary.BigEndian.Uint16(data[11:13]))
	body := data[recordHeaderLen:]
	if recLen > len(body) {
		return ch, ErrTruncated
	}
	body = body[:recLen]
	if len(body) < handshakeHeaderLen {
		return ch, ErrTruncated
	}
	if body[0] != handshakeClientHello {
		return ch, fmt.Errorf("dtls: handshake type %d is not ClientHello", body[0])
	}
	hsLen := u24(body[1:4])
	ch.MessageSeq = binary.BigEndian.Uint16(body[4:6])
	if u24(body[6:9]) != 0 || u24(body[9:12]) != hsLen {
		return ch, errors.New("dtls: fragmented ClientHello")
	}
	if hsLen > len(body)-handshakeHeaderLen {
		return ch, ErrTruncated
	}
	return ch, ch.parseBody(body[handshakeHeaderLen : handshakeHeaderLen+hsLen])
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n > len(r.b) {
		r.err = ErrTruncated
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if b := r.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (r *reader) u16() int {
	if b := r.take(2); b != nil {
		return int(binary.BigEndian.Uint16(b))
	}
	return 0
}

func (ch *ClientHello) parseBody(b []byte) error {
	r := &reader{b: b}
	ch.ClientVersion = uint16(r.u16())
	ch.Random = clone(r.take(32))
	ch.SessionID = clone(r.take(r.u8()))
	ch.Cookie = clone(r.take(r.u8()))
	suites := r.take(r.u16())
	for i := 0; i+1 < len(suites); i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(suites[i:]))
	}
	ch.Compression = clone(r.take(r.u8()))
	if r.err != nil {
		return r.err
	}
	if len(r.b) == 0 {
		return nil
	}
	exts := &reader{b: r.take(r.u16())}
	if r.err != nil {
		return r.err
	}
	for len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.take(exts.u16())
		if exts.err != nil {
			return exts.err
		}
		ch.Extensions = append(ch.Extensions, Extension{Type: uint16(typ), Data: clone(data)})
		if typ == extServerName && ch.ServerName == "" {
			ch.ServerName = parseServerName(data)
		}
	}
	return nil
}

// parseServerName returns the first host_name entry of an SNI extension.
func parseServerName(b []byte) string {
	r := &reader{b: b}
	list := &reader{b: r.take(r.u16())}
	for len(list.b) > 0 {
		typ := list.u8()
		name := list.take(list.u16())
		if list.err != nil {
			return ""
		}
		if typ == 0 {
			return string(name)
		}
	}
	return ""
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// Cookie derives the stateless HelloVerifyRequest cookie for a client address:
// the first CookieLen bytes of HMAC-SHA256(secret, ip || port).
func Cookie(secret []byte, ip net.IP, port int) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(ip.To16())
	mac.Write(binary.BigEndian.AppendUint16(nil, uint16(port)))
	return mac.Sum(nil)[:CookieLen]
}

// BuildHelloVerifyRequest builds an epoch-0 HelloVerifyRequest record. The
// record sequence number echoes the ClientHello's; message_seq is 0 and the
// message is unfragmented. The record version is DTLS 1.0, as RFC 6347
// recommends for interoperability, and server_version is DTLS 1.0.
func BuildHelloVerifyRequest(recordSeq uint64, cookie []byte) []byte {
	bodyLen := 2 + 1 + len(cookie)
	out := make([]byte, 0, recordHeaderLen+handshakeHeaderLen+bodyLen)
	out = append(out, contentTypeHandshake)
	out = binary.BigEndian.AppendUint16(out, VersionDTLS10)
	out = binary.BigEndian.AppendUint16(out, 0) // epoch
	out = append(out, byte(recordSeq>>40), byte(recordSeq>>32), byte(recordSeq>>24), byte(recordSeq>>16), byte(recordSeq>>8), byte(recordSeq))
	out = binary.BigEndian.AppendUint16(out, uint16(handshakeHeaderLen+bodyLen))
	out = append(out, handshakeHelloVerifyRequest, 0, 0, byte(bodyLen))
	out = binary.BigEndian.AppendUint16(out, 0)     // message_seq
	out = append(out, 0, 0, 0, 0, 0, byte(bodyLen)) // fragment_offset, fragment_length
	out = binary.BigEndian.AppendUint16(out, VersionDTLS10)
	out = append(out, byte(len(cookie)))
	return append(out, cookie...)
}

// VersionString names a DTLS wire version, or formats it as hex.
func VersionString(v uint16) string {
	switch v {
	case VersionDTLS10:
		return "DTLS 1.0"
	case VersionDTLS12:
		return "DTLS 1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}
