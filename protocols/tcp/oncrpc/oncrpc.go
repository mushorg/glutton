// Package oncrpc parses ONC RPC (RFC 5531) calls and builds portmapper /
// rpcbind (program 100000, RFC 1833) replies. It is shared by the TCP handler
// (record-marked stream) and the UDP handler (one message per datagram).
package oncrpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	MsgCall  = 0
	MsgReply = 1

	ProgPortmap = 100000
	ProgStatus  = 100024

	ProtTCP = 6
	ProtUDP = 17

	AuthSysFlavor = 1

	// MaxFragments bounds the record-marking fragments of one TCP message.
	MaxFragments = 16

	maxAuthBody  = 400 // RFC 5531 opaque_auth limit
	maxXDRString = 255
	maxAuthGIDs  = 16
)

var (
	ErrMalformed        = errors.New("oncrpc: malformed message")
	ErrRecordTooLarge   = errors.New("oncrpc: record exceeds size cap")
	ErrTooManyFragments = errors.New("oncrpc: too many record fragments")
)

// AuthSys is an AUTH_SYS (AUTH_UNIX) credential body.
type AuthSys struct {
	Stamp       uint32
	MachineName string
	UID         uint32
	GID         uint32
	GIDs        []uint32
}

// Call is an RPC call header. Args holds the procedure arguments.
type Call struct {
	XID        uint32
	MsgType    uint32
	RPCVersion uint32
	Program    uint32
	Version    uint32
	Procedure  uint32
	CredFlavor uint32
	VerfFlavor uint32
	AuthSys    *AuthSys // set when CredFlavor is AUTH_SYS and its body parses
	Args       []byte
	// Header is true when RPCVersion through Procedure were decoded. The call
	// may still be malformed (truncated auth verifier, etc.).
	Header bool
	// Cred is true when CredFlavor and its opaque body were decoded.
	Cred bool
}

// Query holds the arguments of GETPORT (v2) or GETADDR/GETVERSADDR (v3/v4),
// and of SET/UNSET.
type Query struct {
	Program uint32
	Version uint32
	Netid   string // "tcp"/"udp" for a v2 protocol number, the netid otherwise
	Port    uint32 // v2 only
	Addr    string // v3/v4 universal address
	Owner   string // v3/v4 only
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) u32() (uint32, error) {
	if len(d.b)-d.off < 4 {
		return 0, ErrMalformed
	}
	v := binary.BigEndian.Uint32(d.b[d.off:])
	d.off += 4
	return v, nil
}

func (d *decoder) opaque(limit int) ([]byte, error) {
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(limit) {
		return nil, ErrMalformed
	}
	padded := (int(n) + 3) &^ 3
	if len(d.b)-d.off < padded {
		return nil, ErrMalformed
	}
	v := d.b[d.off : d.off+int(n)]
	d.off += padded
	return v, nil
}

func (d *decoder) str() (string, error) {
	v, err := d.opaque(maxXDRString)
	return string(v), err
}

// Parse decodes an RPC message header. Only calls are decoded past msg_type;
// for a reply the returned Call has XID and MsgType set and no error.
// Truncated or malformed calls still return a Call with whatever header fields
// were readable (Header/Cred mark how far decoding got) plus ErrMalformed.
func Parse(b []byte) (*Call, error) {
	d := &decoder{b: b}
	c := &Call{}
	var err error
	if c.XID, err = d.u32(); err != nil {
		return nil, err
	}
	if c.MsgType, err = d.u32(); err != nil {
		return nil, err
	}
	if c.MsgType != MsgCall {
		if c.MsgType != MsgReply {
			return c, ErrMalformed
		}
		return c, nil
	}
	for _, f := range []*uint32{&c.RPCVersion, &c.Program, &c.Version, &c.Procedure} {
		if *f, err = d.u32(); err != nil {
			return c, err
		}
	}
	c.Header = true
	if c.CredFlavor, err = d.u32(); err != nil {
		return c, err
	}
	cred, err := d.opaque(maxAuthBody)
	if err != nil {
		return c, err
	}
	c.Cred = true
	if c.CredFlavor == AuthSysFlavor {
		c.AuthSys = parseAuthSys(cred)
	}
	if c.VerfFlavor, err = d.u32(); err != nil {
		return c, err
	}
	if _, err = d.opaque(maxAuthBody); err != nil {
		return c, err
	}
	c.Args = b[d.off:]
	return c, nil
}

func parseAuthSys(b []byte) *AuthSys {
	d := &decoder{b: b}
	a := &AuthSys{}
	var err error
	if a.Stamp, err = d.u32(); err != nil {
		return nil
	}
	if a.MachineName, err = d.str(); err != nil {
		return nil
	}
	if a.UID, err = d.u32(); err != nil {
		return nil
	}
	if a.GID, err = d.u32(); err != nil {
		return nil
	}
	n, err := d.u32()
	if err != nil || n > maxAuthGIDs {
		return nil
	}
	for i := uint32(0); i < n; i++ {
		g, err := d.u32()
		if err != nil {
			return nil
		}
		a.GIDs = append(a.GIDs, g)
	}
	return a
}

var authNames = map[uint32]string{
	0:      "AUTH_NONE",
	1:      "AUTH_SYS",
	2:      "AUTH_SHORT",
	3:      "AUTH_DH",
	4:      "AUTH_KERB",
	5:      "AUTH_RSA",
	6:      "RPCSEC_GSS",
	390003: "AUTH_KERB5",
}

// AuthName names an auth flavor.
func AuthName(flavor uint32) string {
	if n, ok := authNames[flavor]; ok {
		return n
	}
	return "AUTH_" + strconv.FormatUint(uint64(flavor), 10)
}

var pmapProcs = []string{"NULL", "SET", "UNSET", "GETPORT", "DUMP", "CALLIT"}

var rpcbProcs = []string{"NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "GETTIME",
	"UADDR2TADDR", "TADDR2UADDR", "GETVERSADDR", "INDIRECT", "GETADDRLIST", "GETSTAT"}

// Command names the call: PMAPPROC_* for portmapper v2, RPCBPROC_* for
// rpcbind v3/v4, REPLY for a reply message and CALL for other programs.
func (c *Call) Command() string {
	if c.MsgType == MsgReply {
		return "REPLY"
	}
	if c.Program != ProgPortmap {
		return "CALL"
	}
	prefix, names := "RPCBPROC_", rpcbProcs
	if c.Version <= 2 {
		prefix, names = "PMAPPROC_", pmapProcs
	}
	if c.Version == 4 && c.Procedure == 5 {
		return prefix + "BCAST"
	}
	if int64(c.Procedure) < int64(len(names)) {
		return prefix + names[c.Procedure]
	}
	return prefix + strconv.FormatUint(uint64(c.Procedure), 10)
}

// ParseQuery decodes the arguments of SET, UNSET, GETPORT, GETADDR and
// GETVERSADDR. It returns nil, nil for other portmapper procedures.
func ParseQuery(c *Call) (*Query, error) {
	if c.MsgType != MsgCall || c.Program != ProgPortmap {
		return nil, nil
	}
	d := &decoder{b: c.Args}
	q := &Query{}
	var err error
	switch {
	case c.Version == 2 && c.Procedure >= 1 && c.Procedure <= 3:
		var prot uint32
		for _, f := range []*uint32{&q.Program, &q.Version, &prot, &q.Port} {
			if *f, err = d.u32(); err != nil {
				return nil, err
			}
		}
		q.Netid = protName(prot)
		return q, nil
	case (c.Version == 3 || c.Version == 4) && (c.Procedure >= 1 && c.Procedure <= 3 || c.Version == 4 && c.Procedure == 9):
		if q.Program, err = d.u32(); err != nil {
			return nil, err
		}
		if q.Version, err = d.u32(); err != nil {
			return nil, err
		}
		for _, f := range []*string{&q.Netid, &q.Addr, &q.Owner} {
			if *f, err = d.str(); err != nil {
				return nil, err
			}
		}
		return q, nil
	}
	return nil, nil
}

func protName(prot uint32) string {
	switch prot {
	case ProtTCP:
		return "tcp"
	case ProtUDP:
		return "udp"
	}
	return strconv.FormatUint(uint64(prot), 10)
}

// Mapping is one registered service.
type Mapping struct {
	Program uint32
	Version uint32
	Prot    uint32
	Port    uint16
	Owner   string
}

// Mappings returns the registered services in rpcinfo -p order: rpcbind
// v4/v3/v2 on 111 and rpc.statd on ports derived from seed (a stable
// per-sensor value), so sensors do not share one statd port pair.
func Mappings(seed []byte) []Mapping {
	h := fnv.New64a()
	_, _ = h.Write(seed)
	sum := h.Sum64()
	// Linux ephemeral range 32768-60999.
	udpPort := uint16(32768 + sum%28232)
	tcpPort := uint16(32768 + (sum>>32)%28232)
	if tcpPort == udpPort {
		tcpPort++
	}
	var m []Mapping
	for _, prot := range []uint32{ProtTCP, ProtUDP} {
		for v := uint32(4); v >= 2; v-- {
			m = append(m, Mapping{Program: ProgPortmap, Version: v, Prot: prot, Port: 111, Owner: "superuser"})
		}
	}
	return append(m,
		Mapping{Program: ProgStatus, Version: 1, Prot: ProtUDP, Port: udpPort, Owner: "29"},
		Mapping{Program: ProgStatus, Version: 1, Prot: ProtTCP, Port: tcpPort, Owner: "29"},
	)
}

// Env is the server state a reply depends on.
type Env struct {
	Mappings []Mapping
	LocalIP  net.IP // the address the client reached, used in GETADDR uaddrs
	Now      time.Time
}

// find returns the mapping for prog on netid, preferring vers. Like rpcbind's
// find_service, another version of the same program is returned when vers is
// not registered.
func (e Env) find(prog, vers uint32, netid string) (Mapping, bool) {
	var fallback Mapping
	found := false
	for _, m := range e.Mappings {
		if m.Program != prog || protName(m.Prot) != netid {
			continue
		}
		if m.Version == vers {
			return m, true
		}
		if !found {
			fallback, found = m, true
		}
	}
	return fallback, found
}

// UAddr formats an RFC 5665 universal address: host.p1.p2.
func UAddr(ip net.IP, port uint16) string {
	host := "0.0.0.0"
	if ip != nil && !ip.IsUnspecified() {
		host = ip.String()
	}
	return fmt.Sprintf("%s.%d.%d", host, port>>8, port&0xff)
}

type encoder struct{ b []byte }

func (e *encoder) u32(v ...uint32) {
	for _, x := range v {
		e.b = binary.BigEndian.AppendUint32(e.b, x)
	}
}

func (e *encoder) str(s string) {
	e.u32(uint32(len(s)))
	e.b = append(e.b, s...)
	for len(e.b)%4 != 0 {
		e.b = append(e.b, 0)
	}
}

const (
	msgAccepted = 0
	msgDenied   = 1

	acceptSuccess      = 0
	acceptProgUnavail  = 1
	acceptProgMismatch = 2
	acceptProcUnavail  = 3
	acceptGarbageArgs  = 4

	rejectRPCMismatch = 0
)

func accepted(xid, stat uint32) *encoder {
	e := &encoder{}
	e.u32(xid, MsgReply, msgAccepted, 0, 0, stat) // AUTH_NONE verifier
	return e
}

// Reply builds the RPC reply body (without record mark) for a call, and the
// outcome name for the write frame. It returns nil for messages a server does
// not answer (replies, non-calls).
func Reply(c *Call, env Env) ([]byte, string) {
	if c == nil || c.MsgType != MsgCall {
		return nil, ""
	}
	if c.RPCVersion != 2 {
		e := &encoder{}
		e.u32(c.XID, MsgReply, msgDenied, rejectRPCMismatch, 2, 2)
		return e.b, "RPC_MISMATCH"
	}
	if c.Program != ProgPortmap {
		return accepted(c.XID, acceptProgUnavail).b, "PROG_UNAVAIL"
	}
	if c.Version < 2 || c.Version > 4 {
		e := accepted(c.XID, acceptProgMismatch)
		e.u32(2, 4)
		return e.b, "PROG_MISMATCH"
	}
	q, err := ParseQuery(c)
	if err != nil {
		return accepted(c.XID, acceptGarbageArgs).b, "GARBAGE_ARGS"
	}
	e := accepted(c.XID, acceptSuccess)
	switch {
	case c.Procedure == 0:
	case c.Procedure == 1 || c.Procedure == 2:
		// rpcbind refuses SET/UNSET from non-local callers.
		e.u32(0)
	case c.Version == 2 && c.Procedure == 3:
		port := uint32(0)
		if m, ok := env.find(q.Program, q.Version, q.Netid); ok {
			port = uint32(m.Port)
		}
		e.u32(port)
	case c.Version == 2 && c.Procedure == 4:
		for _, m := range env.Mappings {
			e.u32(1, m.Program, m.Version, m.Prot, uint32(m.Port))
		}
		e.u32(0)
	case c.Procedure == 3 || c.Version == 4 && c.Procedure == 9:
		uaddr := ""
		if m, ok := env.find(q.Program, q.Version, q.Netid); ok {
			uaddr = UAddr(env.LocalIP, m.Port)
		}
		e.str(uaddr)
	case c.Procedure == 4:
		for _, m := range env.Mappings {
			e.u32(1, m.Program, m.Version)
			e.str(protName(m.Prot))
			e.str(UAddr(nil, m.Port))
			e.str(m.Owner)
		}
		e.u32(0)
	case c.Procedure == 6:
		e.u32(uint32(env.Now.Unix()))
	default:
		return accepted(c.XID, acceptProcUnavail).b, "PROC_UNAVAIL"
	}
	return e.b, "SUCCESS"
}

// Frame prepends a last-fragment record mark (RFC 5531 §11).
func Frame(body []byte) []byte {
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), 0x80000000|uint32(len(body)))
	return append(out, body...)
}

// ReadRecord reads one record-marked message. raw holds the wire bytes read
// (marks included) and body the reassembled fragments; both are set on error
// when bytes were read. A record over maxBody is read up to the cap, flagged
// truncated, and ends with ErrRecordTooLarge.
func ReadRecord(r io.Reader, maxBody int) (raw, body []byte, truncated bool, err error) {
	var mark [4]byte
	for frag := 0; ; frag++ {
		if frag == MaxFragments {
			return raw, body, false, ErrTooManyFragments
		}
		n, err := io.ReadFull(r, mark[:])
		raw = append(raw, mark[:n]...)
		if err != nil {
			if n == 0 && frag > 0 {
				err = io.ErrUnexpectedEOF
			}
			return raw, body, false, err
		}
		v := binary.BigEndian.Uint32(mark[:])
		size, last := int(v&0x7fffffff), v&0x80000000 != 0
		want := min(size, maxBody-len(body))
		buf := make([]byte, want)
		n, err = io.ReadFull(r, buf)
		raw, body = append(raw, buf[:n]...), append(body, buf[:n]...)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return raw, body, want < size, err
		}
		if want < size {
			return raw, body, true, ErrRecordTooLarge
		}
		if last {
			return raw, body, false, nil
		}
	}
}
