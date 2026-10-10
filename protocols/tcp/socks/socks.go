// Package socks parses SOCKS4, SOCKS4a and SOCKS5 (RFC 1928, RFC 1929)
// client messages and builds the server replies a proxy would send.
package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	Version4 = 0x04
	Version5 = 0x05

	CmdConnect   = 0x01
	CmdBind      = 0x02
	CmdAssociate = 0x03 // SOCKS5 UDP ASSOCIATE

	MethodNoAuth       = 0x00
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xff

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	// SOCKS4 reply codes
	Reply4Granted  = 0x5a
	Reply4Rejected = 0x5b

	// SOCKS5 reply codes
	Reply5Succeeded           = 0x00
	Reply5CommandNotSupported = 0x07
	Reply5AddrNotSupported    = 0x08

	// maxField bounds the NUL-terminated SOCKS4 userid and SOCKS4a hostname.
	maxField = 255
	// MaxSOCKS4Request is the longest SOCKS4a request LooksLikeSOCKS accepts.
	MaxSOCKS4Request = 8 + 2*(maxField+1)
)

var (
	ErrVersion      = errors.New("socks: unsupported version")
	ErrFieldTooLong = errors.New("socks: field exceeds 255 bytes")
	ErrBadAuthVer   = errors.New("socks: unsupported auth version")
	ErrBadReserved  = errors.New("socks: non-zero reserved byte")
	ErrBadAddrType  = errors.New("socks: unsupported address type")
	ErrNoMethods    = errors.New("socks: greeting offers no methods")
)

// Request is a parsed SOCKS4/4a CONNECT/BIND or SOCKS5 request.
type Request struct {
	Version byte
	Command byte
	Atyp    byte // SOCKS5 only
	Host    string
	Port    uint16
	User    string // SOCKS4 userid
	SOCKS4a bool
	Raw     []byte // wire bytes, version byte included
}

// Addr returns host:port of the requested destination.
func (r Request) Addr() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// Name is the frame command: socks4-connect, socks4a-bind, socks5-connect, ...
func (r Request) Name() string {
	prefix := "socks5"
	if r.Version == Version4 {
		prefix = "socks4"
		if r.SOCKS4a {
			prefix = "socks4a"
		}
	}
	switch r.Command {
	case CmdConnect:
		return prefix + "-connect"
	case CmdBind:
		return prefix + "-bind"
	case CmdAssociate:
		return prefix + "-udp-associate"
	}
	return prefix + "-cmd-" + strconv.Itoa(int(r.Command))
}

// Greeting is a SOCKS5 method-selection message.
type Greeting struct {
	Methods []byte
	Raw     []byte
}

// Auth is an RFC 1929 username/password message. The password is not kept;
// Raw has the password bytes masked with '*'.
type Auth struct {
	User string
	Raw  []byte
}

// recorder keeps every byte read so frames carry the wire bytes.
type recorder struct {
	r   *bufio.Reader
	raw []byte
}

func (rc *recorder) full(n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := io.ReadFull(rc.r, b)
	rc.raw = append(rc.raw, b[:got]...)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (rc *recorder) cstring() (string, error) {
	start := len(rc.raw)
	for i := 0; i <= maxField; i++ {
		c, err := rc.r.ReadByte()
		if err != nil {
			return "", err
		}
		rc.raw = append(rc.raw, c)
		if c == 0 {
			return string(rc.raw[start : len(rc.raw)-1]), nil
		}
	}
	return "", ErrFieldTooLong
}

// ReadVersion reads the first byte of a client message.
func ReadVersion(r *bufio.Reader) (byte, error) {
	return r.ReadByte()
}

// ReadSOCKS4 reads a SOCKS4/4a request whose version byte was already read.
// On error, Raw still holds the bytes that were read.
func ReadSOCKS4(r *bufio.Reader) (Request, error) {
	rc := &recorder{r: r, raw: []byte{Version4}}
	req := Request{Version: Version4}
	hdr, err := rc.full(7)
	if err != nil {
		req.Raw = rc.raw
		return req, err
	}
	req.Command = hdr[0]
	req.Port = binary.BigEndian.Uint16(hdr[1:3])
	ip := net.IP(hdr[3:7])
	req.Host = ip.String()
	if req.User, err = rc.cstring(); err != nil {
		req.Raw = rc.raw
		return req, err
	}
	// SOCKS4a: DSTIP 0.0.0.x with x != 0 means a hostname follows the userid
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		req.SOCKS4a = true
		if req.Host, err = rc.cstring(); err != nil {
			req.Raw = rc.raw
			return req, err
		}
	}
	req.Raw = rc.raw
	return req, nil
}

// ReadGreeting reads a SOCKS5 method-selection message whose version byte
// was already read.
func ReadGreeting(r *bufio.Reader) (Greeting, error) {
	rc := &recorder{r: r, raw: []byte{Version5}}
	n, err := rc.full(1)
	if err != nil {
		return Greeting{Raw: rc.raw}, err
	}
	methods, err := rc.full(int(n[0]))
	if err != nil {
		return Greeting{Raw: rc.raw}, err
	}
	if len(methods) == 0 {
		return Greeting{Raw: rc.raw}, ErrNoMethods
	}
	return Greeting{Methods: methods, Raw: rc.raw}, nil
}

// ReadAuth reads an RFC 1929 username/password request. The password is
// discarded and masked in Raw.
func ReadAuth(r *bufio.Reader) (Auth, error) {
	rc := &recorder{r: r}
	ver, err := rc.full(1)
	if err != nil {
		return Auth{Raw: rc.raw}, err
	}
	if ver[0] != 0x01 {
		return Auth{Raw: rc.raw}, ErrBadAuthVer
	}
	ulen, err := rc.full(1)
	if err != nil {
		return Auth{Raw: rc.raw}, err
	}
	user, err := rc.full(int(ulen[0]))
	if err != nil {
		return Auth{Raw: rc.raw}, err
	}
	auth := Auth{User: string(user)}
	plen, err := rc.full(1)
	if err != nil {
		auth.Raw = rc.raw
		return auth, err
	}
	start := len(rc.raw)
	_, err = rc.full(int(plen[0]))
	for i := start; i < len(rc.raw); i++ {
		rc.raw[i] = '*'
	}
	auth.Raw = rc.raw
	return auth, err
}

// ReadSOCKS5 reads a SOCKS5 request (VER CMD RSV ATYP DST.ADDR DST.PORT).
func ReadSOCKS5(r *bufio.Reader) (Request, error) {
	rc := &recorder{r: r}
	req := Request{}
	hdr, err := rc.full(4)
	if err != nil {
		req.Raw = rc.raw
		return req, err
	}
	req.Version, req.Command, req.Atyp = hdr[0], hdr[1], hdr[3]
	if req.Version != Version5 {
		req.Raw = rc.raw
		return req, ErrVersion
	}
	if hdr[2] != 0 {
		req.Raw = rc.raw
		return req, ErrBadReserved
	}
	switch req.Atyp {
	case AtypIPv4:
		b, err := rc.full(net.IPv4len)
		if err != nil {
			req.Raw = rc.raw
			return req, err
		}
		req.Host = net.IP(b).String()
	case AtypIPv6:
		b, err := rc.full(net.IPv6len)
		if err != nil {
			req.Raw = rc.raw
			return req, err
		}
		req.Host = net.IP(b).String()
	case AtypDomain:
		n, err := rc.full(1)
		if err != nil {
			req.Raw = rc.raw
			return req, err
		}
		b, err := rc.full(int(n[0]))
		if err != nil {
			req.Raw = rc.raw
			return req, err
		}
		req.Host = string(b)
	default:
		req.Raw = rc.raw
		return req, ErrBadAddrType
	}
	p, err := rc.full(2)
	req.Raw = rc.raw
	if err != nil {
		return req, err
	}
	req.Port = binary.BigEndian.Uint16(p)
	return req, nil
}

// SelectMethod prefers username/password so credentials are captured, then
// no authentication; anything else gets "no acceptable methods".
func SelectMethod(methods []byte) byte {
	noAuth := false
	for _, m := range methods {
		if m == MethodUserPass {
			return MethodUserPass
		}
		if m == MethodNoAuth {
			noAuth = true
		}
	}
	if noAuth {
		return MethodNoAuth
	}
	return MethodNoAcceptable
}

// MethodReply builds the SOCKS5 method-selection reply.
func MethodReply(method byte) []byte {
	return []byte{Version5, method}
}

// AuthReply builds an RFC 1929 reply; status 0 is success.
func AuthReply(status byte) []byte {
	return []byte{0x01, status}
}

// Reply4 builds the 8-byte SOCKS4 reply: VN=0, CD, DSTPORT, DSTIP.
func Reply4(code byte, ip net.IP, port uint16) []byte {
	b := make([]byte, 8)
	b[1] = code
	binary.BigEndian.PutUint16(b[2:4], port)
	if ip4 := ip.To4(); ip4 != nil {
		copy(b[4:], ip4)
	}
	return b
}

// Reply5 builds a SOCKS5 reply with an IPv4 bound address.
func Reply5(code byte, ip net.IP, port uint16) []byte {
	b := []byte{Version5, code, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	if ip4 := ip.To4(); ip4 != nil {
		copy(b[4:8], ip4)
	}
	binary.BigEndian.PutUint16(b[8:10], port)
	return b
}

// LooksLikeSOCKS reports whether data is exactly one SOCKS4/4a request
// (CONNECT or BIND, non-zero port, NUL-terminated userid and hostname) or a
// SOCKS5 method-selection message with exactly NMETHODS known method bytes.
// Clients send this message and then wait for the reply, so the first
// segment holds it alone; extra bytes mean another protocol.
func LooksLikeSOCKS(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	switch data[0] {
	case Version4:
		return looksLikeSOCKS4(data)
	case Version5:
		n := int(data[1])
		if n == 0 || len(data) != 2+n {
			return false
		}
		for _, m := range data[2:] {
			// 0x00-0x09 are IANA-assigned, 0x80-0xFE private methods
			if m > 0x09 && (m < 0x80 || m == 0xff) {
				return false
			}
		}
		return true
	}
	return false
}

func looksLikeSOCKS4(data []byte) bool {
	if len(data) < 9 || len(data) > MaxSOCKS4Request {
		return false
	}
	if data[1] != CmdConnect && data[1] != CmdBind {
		return false
	}
	if data[2] == 0 && data[3] == 0 {
		return false
	}
	ip := data[4:8]
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return false
	}
	end, ok := nulField(data, 8)
	if !ok {
		return false
	}
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 {
		hostStart := end
		end, ok = nulField(data, hostStart)
		if !ok || end-1 == hostStart {
			return false
		}
	}
	return end == len(data)
}

// nulField returns the offset after the NUL terminating the field at start.
func nulField(data []byte, start int) (int, bool) {
	for i := start; i < len(data) && i-start <= maxField; i++ {
		if data[i] == 0 {
			return i + 1, true
		}
	}
	return 0, false
}
