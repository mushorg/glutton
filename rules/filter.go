package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// flow is what a rule filter sees: the transport protocol and the two
// endpoints of a TCP or UDP connection. Addresses are unmapped and zoneless.
type flow struct {
	proto    uint8 // IP protocol number: 6 (TCP) or 17 (UDP)
	src, dst netip.AddrPort
}

// IP protocol numbers the filter grammar knows.
const (
	protoICMP   uint8 = 1
	protoTCP    uint8 = 6
	protoUDP    uint8 = 17
	protoICMPv6 uint8 = 58
	protoSCTP   uint8 = 132
)

// direction is the src/dst qualifier of a host, net, port or portrange
// primitive.
type direction uint8

const (
	dirSrcOrDst direction = iota // the default
	dirSrc
	dirDst
	dirSrcAndDst
)

type op uint8

const (
	opAnd    op = iota // l and r
	opOr               // l or r
	opNot              // not l
	opFamily           // ip (v4) or ip6
	opProto            // tcp, udp, sctp, icmp, icmp6
	opPort             // port and portrange; proto 0 is any of TCP, UDP, SCTP
	opNet              // host (a full-length prefix) and net
)

// matcher is one node of a compiled filter. It is a single concrete type,
// not an interface, so evaluating a filter does not make the flow escape.
type matcher struct {
	op     op
	l, r   *matcher
	v4     bool
	proto  uint8
	dir    direction
	lo, hi uint16
	prefix netip.Prefix
}

func (m *matcher) match(f *flow) bool {
	switch m.op {
	case opAnd:
		return m.l.match(f) && m.r.match(f)
	case opOr:
		return m.l.match(f) || m.r.match(f)
	case opNot:
		return !m.l.match(f)
	case opFamily:
		return f.src.Addr().Is4() == m.v4
	case opProto:
		return f.proto == m.proto
	case opPort:
		if m.proto != 0 && f.proto != m.proto {
			return false
		}
		return m.dirMatch(m.inRange(f.src.Port()), m.inRange(f.dst.Port()))
	default: // opNet; the prefix's address family doubles as the ip/ip6 check
		return m.dirMatch(m.prefix.Contains(f.src.Addr()), m.prefix.Contains(f.dst.Addr()))
	}
}

func (m *matcher) inRange(p uint16) bool { return p >= m.lo && p <= m.hi }

func (m *matcher) dirMatch(src, dst bool) bool {
	switch m.dir {
	case dirSrc:
		return src
	case dirDst:
		return dst
	case dirSrcAndDst:
		return src && dst
	default:
		return src || dst
	}
}

// qualifiers are the keywords in front of an id, e.g. "tcp dst port" in
// "tcp dst port 23". A bare id after and/or reuses the previous term's.
type qualifiers struct {
	proto string // "", ip, ip6, tcp, udp or sctp
	dir   direction
	typ   string // host, net, port or portrange
}

// compileFilter parses a pcap filter expression (see pcap-filter(7)) into a
// matcher. It supports the part of the language that a TCP or UDP flow can
// answer: the ip, ip6, tcp, udp, sctp, icmp and icmp6 primitives; host, net,
// port and portrange with optional ip/ip6/tcp/udp/sctp and src/dst
// qualifiers; and, or, not and parentheses. It follows libpcap where the
// language is surprising: and and or have equal precedence and group left
// to right, a bare id inherits the qualifiers of the term before it, and
// numbers with a leading 0 are octal. Everything else, such as byte offsets
// (tcp[13]), length tests, link-layer primitives, port names and host
// names, is rejected rather than silently never matching.
func compileFilter(expr string) (*matcher, error) {
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty filter expression")
	}
	p := &filterParser{toks: toks}
	m, _, err := p.expr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("syntax error at %q", p.toks[p.pos])
	}
	return m, nil
}

// tokenize splits a filter into words, parentheses and the !, && and ||
// operators.
func tokenize(expr string) ([]string, error) {
	var toks []string
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			toks = append(toks, expr[i:i+1])
			i++
		case c == '!':
			if i+1 < len(expr) && expr[i+1] == '=' {
				return nil, fmt.Errorf("unsupported operator %q", "!=")
			}
			toks = append(toks, "!")
			i++
		case c == '&' || c == '|':
			if i+1 >= len(expr) || expr[i+1] != c {
				return nil, fmt.Errorf("unsupported operator %q", string(c))
			}
			toks = append(toks, expr[i:i+2])
			i += 2
		default:
			j := i
			for j < len(expr) && !strings.ContainsRune(" \t\n\r()!&|", rune(expr[j])) {
				j++
			}
			toks = append(toks, expr[i:j])
			i = j
		}
	}
	return toks, nil
}

func isAnd(t string) bool { return t == "and" || t == "&&" }
func isOr(t string) bool  { return t == "or" || t == "||" }
func isNot(t string) bool { return t == "not" || t == "!" }

// keywords are the words that start a term; anything else in term position
// is an id.
var keywords = map[string]bool{
	"and": true, "or": true, "not": true,
	"ip": true, "ip6": true, "tcp": true, "udp": true, "sctp": true, "icmp": true, "icmp6": true,
	"src": true, "dst": true,
	"host": true, "net": true, "port": true, "portrange": true,
}

// unsupported lists pcap-filter keywords the rule filters reject because a
// TCP or UDP flow cannot answer them, so the error says so instead of
// calling them a syntax error.
var unsupported = map[string]bool{
	"ether": true, "fddi": true, "tr": true, "wlan": true, "arp": true, "rarp": true,
	"vlan": true, "mpls": true, "pppoed": true, "pppoes": true, "geneve": true,
	"decnet": true, "atalk": true, "aarp": true, "ipx": true, "iso": true, "stp": true,
	"netbeui": true, "lat": true, "moprc": true, "mopdl": true, "igmp": true, "igrp": true,
	"pim": true, "ah": true, "esp": true, "vrrp": true, "carp": true, "radio": true,
	"proto": true, "protochain": true, "gateway": true, "broadcast": true, "multicast": true,
	"less": true, "greater": true, "len": true, "inbound": true, "outbound": true,
	"ifname": true, "on": true, "rnr": true, "rulenum": true, "reason": true, "rset": true,
	"ruleset": true, "srnr": true, "subrulenum": true, "action": true, "type": true,
	"subtype": true, "dir": true, "addr1": true, "addr2": true, "addr3": true, "addr4": true,
	"ra": true, "ta": true, "mask": true, "sio": true, "opc": true, "dpc": true, "sls": true,
	"llc": true, "hdpc": true, "hopc": true, "hsio": true, "hsls": true, "metac": true,
}

type filterParser struct {
	toks []string
	pos  int
}

func (p *filterParser) peek(off int) string {
	if p.pos+off < len(p.toks) {
		return p.toks[p.pos+off]
	}
	return ""
}

func (p *filterParser) next() string {
	t := p.peek(0)
	p.pos++
	return t
}

// isID reports whether t can only be an id: not a keyword, operator or
// parenthesis.
func isID(t string) bool {
	return t != "" && t != "(" && t != ")" && t != "!" && t != "&&" && t != "||" && !keywords[t]
}

// expr parses terms joined by and/or, left to right with equal precedence.
// It returns the qualifiers of the last term so a bare id can inherit them.
func (p *filterParser) expr() (*matcher, *qualifiers, error) {
	m, q, err := p.term()
	if err != nil {
		return nil, nil, err
	}
	for isAnd(p.peek(0)) || isOr(p.peek(0)) {
		op := p.next()
		r, rq, err := p.operand(q)
		if err != nil {
			return nil, nil, err
		}
		if isAnd(op) {
			m = &matcher{op: opAnd, l: m, r: r}
		} else {
			m = &matcher{op: opOr, l: m, r: r}
		}
		q = rq
	}
	return m, q, nil
}

// operand parses what follows and/or: a term, or a bare (possibly negated)
// id that reuses the qualifiers q of the term before the operator.
func (p *filterParser) operand(q *qualifiers) (*matcher, *qualifiers, error) {
	negs := 0
	for isNot(p.peek(negs)) {
		negs++
	}
	if !isID(p.peek(negs)) {
		return p.term()
	}
	p.pos += negs
	id := p.next()
	if q == nil {
		return nil, nil, fmt.Errorf("%q needs a qualifier such as port or host", id)
	}
	m, err := primitive(*q, id)
	if err != nil {
		return nil, nil, err
	}
	for range negs {
		m = &matcher{op: opNot, l: m}
	}
	return m, q, nil
}

// term parses a negation, a parenthesized expression or a primitive.
func (p *filterParser) term() (*matcher, *qualifiers, error) {
	t := p.peek(0)
	switch {
	case t == "":
		return nil, nil, fmt.Errorf("unexpected end of filter expression")
	case isNot(t):
		p.next()
		m, q, err := p.term()
		if err != nil {
			return nil, nil, err
		}
		return &matcher{op: opNot, l: m}, q, nil
	case t == "(":
		p.next()
		m, _, err := p.expr()
		if err != nil {
			return nil, nil, err
		}
		if p.next() != ")" {
			return nil, nil, fmt.Errorf("missing ')'")
		}
		// As in libpcap, qualifiers do not carry out of parentheses.
		return m, nil, nil
	}
	return p.primitive()
}

// primitive parses [proto] [dir] [type] id, or a bare protocol keyword.
func (p *filterParser) primitive() (*matcher, *qualifiers, error) {
	q := qualifiers{dir: dirSrcOrDst}
	start := p.pos

	switch t := p.peek(0); t {
	case "ip", "ip6", "tcp", "udp", "sctp":
		q.proto = t
		p.next()
	case "icmp", "icmp6":
		p.next()
		if !isAnd(p.peek(0)) && !isOr(p.peek(0)) && p.peek(0) != ")" && p.peek(0) != "" {
			return nil, nil, fmt.Errorf("syntax error after %q", t)
		}
		if t == "icmp" {
			return &matcher{op: opProto, proto: protoICMP}, nil, nil
		}
		return &matcher{op: opProto, proto: protoICMPv6}, nil, nil
	}

	switch t := p.peek(0); t {
	case "src", "dst":
		p.next()
		q.dir = dirSrc
		if t == "dst" {
			q.dir = dirDst
		}
		// "src or dst" and "src and dst" (either order) are one qualifier.
		other := map[string]string{"src": "dst", "dst": "src"}[t]
		if op := p.peek(0); (isOr(op) || isAnd(op)) && p.peek(1) == other {
			p.pos += 2
			q.dir = dirSrcOrDst
			if isAnd(op) {
				q.dir = dirSrcAndDst
			}
		}
	}

	switch t := p.peek(0); t {
	case "host", "net", "port", "portrange":
		q.typ = t
		p.next()
	}

	if p.pos == start {
		t := p.peek(0)
		switch {
		case unsupported[t] || strings.ContainsAny(t, "[]"):
			return nil, nil, fmt.Errorf("unsupported filter keyword %q", t)
		case t == ")" || isAnd(t) || isOr(t):
			return nil, nil, fmt.Errorf("syntax error at %q", t)
		default:
			return nil, nil, fmt.Errorf("%q needs a qualifier such as port or host", t)
		}
	}

	// A protocol keyword on its own is a primitive, not a qualifier.
	if p.pos == start+1 && q.proto != "" {
		switch q.proto {
		case "ip":
			return &matcher{op: opFamily, v4: true}, nil, nil
		case "ip6":
			return &matcher{op: opFamily, v4: false}, nil, nil
		case "tcp":
			return &matcher{op: opProto, proto: protoTCP}, nil, nil
		case "udp":
			return &matcher{op: opProto, proto: protoUDP}, nil, nil
		default:
			return &matcher{op: opProto, proto: protoSCTP}, nil, nil
		}
	}

	if q.typ == "" {
		q.typ = "host"
	}
	id := p.peek(0)
	if !isID(id) {
		if id == "" {
			return nil, nil, fmt.Errorf("missing value after %q", p.toks[p.pos-1])
		}
		return nil, nil, fmt.Errorf("unsupported value %q after %q", id, p.toks[p.pos-1])
	}
	p.next()
	m, err := primitive(q, id)
	if err != nil {
		return nil, nil, err
	}
	return m, &q, nil
}

// primitive builds the matcher for a qualified id.
func primitive(q qualifiers, id string) (*matcher, error) {
	switch q.typ {
	case "port", "portrange":
		var proto uint8
		switch q.proto {
		case "":
		case "tcp":
			proto = protoTCP
		case "udp":
			proto = protoUDP
		case "sctp":
			proto = protoSCTP
		default:
			return nil, fmt.Errorf("illegal qualifier %q of %q", q.proto, q.typ)
		}
		var lo, hi uint16
		if q.typ == "port" {
			n, err := parsePort(id)
			if err != nil {
				return nil, err
			}
			lo, hi = n, n
		} else {
			a, b, isRange := strings.Cut(id, "-")
			if !isRange {
				n, err := parsePort(id)
				if err != nil {
					return nil, err
				}
				lo, hi = n, n
			} else {
				// libpcap reads both ends of a range as decimal, even
				// with a leading 0.
				var err error
				if lo, err = parseDecimalPort(a); err != nil {
					return nil, err
				}
				if hi, err = parseDecimalPort(b); err != nil {
					return nil, err
				}
				if lo > hi {
					lo, hi = hi, lo
				}
			}
		}
		return &matcher{op: opPort, proto: proto, dir: q.dir, lo: lo, hi: hi}, nil

	default: // host, net
		if q.proto != "" && q.proto != "ip" && q.proto != "ip6" {
			return nil, fmt.Errorf("%q modifier applied to %s", q.proto, q.typ)
		}
		var prefix netip.Prefix
		if q.typ == "net" && strings.Contains(id, "/") {
			pf, err := netip.ParsePrefix(id)
			if err != nil {
				return nil, fmt.Errorf("invalid net %q", id)
			}
			if pf.Masked() != pf {
				return nil, fmt.Errorf("non-network bits set in %q", id)
			}
			prefix = pf
		} else {
			a, err := netip.ParseAddr(id)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("invalid %s %q: want an IP address (host names and partial addresses are not supported)", q.typ, id)
			}
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		if v4 := prefix.Addr().Is4(); (q.proto == "ip" && !v4) || (q.proto == "ip6" && v4) {
			return nil, fmt.Errorf("%q modifier applied to %s %q", q.proto, q.typ, id)
		}
		return &matcher{op: opNet, dir: q.dir, prefix: prefix}, nil
	}
}

// parsePort parses a port number the way libpcap reads numbers: 0x for hex,
// a leading 0 for octal, decimal otherwise. Port names are not supported.
func parsePort(s string) (uint16, error) {
	base, digits := 10, s
	switch {
	case len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, digits = 16, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, digits = 8, s[1:]
	}
	if digits == "" || digits[0] == '+' || digits[0] == '-' || strings.Contains(digits, "_") {
		return 0, fmt.Errorf("invalid port %q: want a number (port names are not supported)", s)
	}
	return portNumber(s, digits, base)
}

// parseDecimalPort parses one end of a portrange.
func parseDecimalPort(s string) (uint16, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid port %q in range: want a decimal number", s)
		}
	}
	return portNumber(s, s, 10)
}

func portNumber(s, digits string, base int) (uint16, error) {
	n, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: want a number (port names are not supported)", s)
	}
	if n > 65535 {
		return 0, fmt.Errorf("illegal port number %d > 65535", n)
	}
	return uint16(n), nil
}
