// Package firebird parses the Firebird/InterBase remote wire protocol (XDR
// over TCP, src/remote/protocol.h) far enough to answer op_connect and
// record op_attach/op_service_attach logins, and builds the server replies.
package firebird

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Operation codes (src/remote/protocol.h).
const (
	OpConnect       = 1
	OpExit          = 2
	OpAccept        = 3
	OpReject        = 4
	OpDisconnect    = 6
	OpResponse      = 9
	OpAttach        = 19
	OpCreate        = 20
	OpDetach        = 21
	OpDummy         = 57
	OpServiceAttach = 82
	OpServiceDetach = 83
)

// Connect versions sent in p_cnct_cversion.
const (
	ConnectVersion2 = 2
	ConnectVersion3 = 3
)

// ConnectPeekLen covers the op_connect fields LooksLikeConnect checks.
const ConnectPeekLen = 16

// maxProtocols bounds the protocol list of an op_connect; clients offer at
// most a dozen.
const maxProtocols = 32

var (
	// ErrTooLong is returned when a packet would pass the read cap.
	ErrTooLong = errors.New("firebird packet exceeds cap")
	// ErrMalformed is returned for a packet whose fields cannot be valid.
	ErrMalformed = errors.New("malformed firebird packet")
	// ErrUnknownOp is returned for an operation whose layout is not parsed.
	ErrUnknownOp = errors.New("unsupported firebird operation")
)

var opNames = map[uint32]string{
	OpConnect:       "connect",
	OpExit:          "exit",
	OpAccept:        "accept",
	OpReject:        "reject",
	OpDisconnect:    "disconnect",
	OpResponse:      "response",
	OpAttach:        "attach",
	OpCreate:        "create",
	OpDetach:        "detach",
	OpDummy:         "dummy",
	OpServiceAttach: "service_attach",
	OpServiceDetach: "service_detach",
}

// OpName returns the command name for an operation code.
func OpName(op uint32) string {
	if name, ok := opNames[op]; ok {
		return name
	}
	return fmt.Sprintf("op_%d", op)
}

// Protocol is one entry of the op_connect protocol list (p_cnct_repeat).
type Protocol struct {
	Version uint32
	Arch    uint32
	MinType uint32
	MaxType uint32
	Weight  uint32
}

// Connect is an op_connect (P_CNCT). The user identification block is
// reduced to its non-secret strings; CNCT_passwd is never kept.
type Connect struct {
	Operation  uint32
	Version    uint32
	ClientArch uint32
	File       string
	Protocols  []Protocol
	OSUser     string // CNCT_user
	Host       string // CNCT_host
	Login      string // CNCT_login (Firebird 3+)
	Plugin     string // CNCT_plugin_name (Firebird 3+)
}

// Attach is an op_attach, op_create or op_service_attach (P_ATCH) with its
// DPB/SPB decoded.
type Attach struct {
	File string
	Params
}

// Packet is one client operation. Raw holds the bytes read for it, also when
// reading failed part way.
type Packet struct {
	Op      uint32
	Raw     []byte
	Connect Connect
	Attach  Attach
}

// xdr reads XDR items while keeping the raw bytes and enforcing the cap.
type xdr struct {
	r   io.Reader
	raw []byte
	max int
}

func (x *xdr) bytes(n int) ([]byte, error) {
	if n < 0 || len(x.raw)+n > x.max {
		return nil, ErrTooLong
	}
	start := len(x.raw)
	x.raw = append(x.raw, make([]byte, n)...)
	m, err := io.ReadFull(x.r, x.raw[start:])
	x.raw = x.raw[:start+m]
	if err != nil {
		return nil, err
	}
	return x.raw[start:], nil
}

func (x *xdr) uint32() (uint32, error) {
	b, err := x.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// opaque reads a counted byte string padded to a multiple of four.
func (x *xdr) opaque() ([]byte, error) {
	n, err := x.uint32()
	if err != nil {
		return nil, err
	}
	if n > uint32(x.max) {
		return nil, ErrTooLong
	}
	b, err := x.bytes(int(n))
	if err != nil {
		return nil, err
	}
	data := append([]byte(nil), b...)
	if _, err := x.bytes(int((4 - n%4) % 4)); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadPacket reads one client operation of at most maxLen bytes. For an
// operation it cannot frame (ErrUnknownOp) Raw also holds whatever the
// client already sent after the opcode.
func ReadPacket(r *bufio.Reader, maxLen int) (Packet, error) {
	x := &xdr{r: r, max: maxLen}
	op, err := x.uint32()
	p := Packet{Op: op}
	if err != nil {
		p.Raw = x.raw
		return p, err
	}
	switch op {
	case OpConnect:
		p.Connect, err = readConnect(x)
	case OpAttach, OpCreate, OpServiceAttach:
		p.Attach, err = readAttach(x, op == OpServiceAttach)
	case OpDetach, OpServiceDetach:
		_, err = x.uint32()
	case OpExit, OpDisconnect, OpDummy:
	default:
		if n := min(r.Buffered(), maxLen-len(x.raw)); n > 0 {
			_, _ = x.bytes(n)
		}
		err = ErrUnknownOp
	}
	p.Raw = x.raw
	return p, err
}

func readConnect(x *xdr) (Connect, error) {
	var c Connect
	var err error
	if c.Operation, err = x.uint32(); err != nil {
		return c, err
	}
	if c.Version, err = x.uint32(); err != nil {
		return c, err
	}
	if c.ClientArch, err = x.uint32(); err != nil {
		return c, err
	}
	file, err := x.opaque()
	if err != nil {
		return c, err
	}
	c.File = string(file)
	count, err := x.uint32()
	if err != nil {
		return c, err
	}
	if count > maxProtocols {
		return c, ErrMalformed
	}
	userID, err := x.opaque()
	if err != nil {
		return c, err
	}
	c.parseUserID(userID)
	for range count {
		var v [5]uint32
		for i := range v {
			if v[i], err = x.uint32(); err != nil {
				return c, err
			}
		}
		c.Protocols = append(c.Protocols, Protocol{Version: v[0], Arch: v[1], MinType: v[2], MaxType: v[3], Weight: v[4]})
	}
	return c, nil
}

// User identification tags (CNCT_*).
const (
	cnctUser       = 1
	cnctHost       = 4
	cnctPluginName = 8
	cnctLogin      = 9
)

// parseUserID keeps the non-secret strings of the user identification block
// (tag, length byte, data).
func (c *Connect) parseUserID(b []byte) {
	for len(b) >= 2 {
		tag, n := b[0], int(b[1])
		if len(b) < 2+n {
			return
		}
		val := string(b[2 : 2+n])
		switch tag {
		case cnctUser:
			c.OSUser = val
		case cnctHost:
			c.Host = val
		case cnctPluginName:
			c.Plugin = val
		case cnctLogin:
			c.Login = val
		}
		b = b[2+n:]
	}
}

func readAttach(x *xdr, service bool) (Attach, error) {
	var a Attach
	if _, err := x.uint32(); err != nil { // p_atch_database
		return a, err
	}
	file, err := x.opaque()
	if err != nil {
		return a, err
	}
	a.File = string(file)
	params, err := x.opaque()
	if err != nil {
		return a, err
	}
	if service {
		a.Params = ParseSPB(params)
	} else {
		a.Params = ParseDPB(params)
	}
	return a, nil
}

// LooksLikeConnect reports whether b starts an op_connect: the opcode, an
// attach/create/service-attach operation and a known connect version.
func LooksLikeConnect(b []byte) bool {
	if len(b) < ConnectPeekLen || binary.BigEndian.Uint32(b) != OpConnect {
		return false
	}
	switch binary.BigEndian.Uint32(b[4:]) {
	case OpAttach, OpCreate, OpServiceAttach:
	default:
		return false
	}
	switch binary.BigEndian.Uint32(b[8:]) {
	case ConnectVersion2, ConnectVersion3:
	default:
		return false
	}
	return binary.BigEndian.Uint32(b[12:]) <= 0xff
}
