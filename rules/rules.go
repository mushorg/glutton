package rules

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	yaml "gopkg.in/yaml.v2"
)

type RuleType int

const (
	UserConnHandler RuleType = iota
	ProxyTCP
	ProxyUDP
	Drop
)

type Config struct {
	Version int   `yaml:"version"`
	Rules   Rules `yaml:"rules"`
}

type Rule struct {
	Match   string `yaml:"match"`
	Type    string `yaml:"type"`
	Target  string `yaml:"target,omitempty"`
	Name    string `yaml:"name,omitempty"`
	Produce *bool  `yaml:"produce,omitempty"` // nil/omitted means true
	// TLS terminates TLS on the connection before a conn_handler runs, so the
	// handler sees plaintext: true for implicit TLS (POP3S), auto to sniff
	// for a ClientHello and serve plaintext otherwise.
	TLS TLSMode `yaml:"tls,omitempty"`

	isInit      bool
	RuleType    RuleType
	ProxyTarget *ProxyTarget `yaml:"-"`
	index       int
	// matcher runs the compiled filter in Go. Unlike pcap.BPF, which writes
	// a shared header on every call, it is stateless and so safe for the TCP
	// and UDP listeners to run concurrently, and it avoids a cgo call per rule.
	matcher *bpf.VM
}

// ShouldProduce reports whether matching sessions should be sent to producers.
// Omitted or nil produce defaults to true.
func (r *Rule) ShouldProduce() bool {
	if r == nil || r.Produce == nil {
		return true
	}
	return *r.Produce
}

// TLSMode selects TLS termination for a conn_handler rule.
type TLSMode int

const (
	// TLSOff passes the connection to the handler unchanged.
	TLSOff TLSMode = iota
	// TLSOn always runs a TLS handshake first (implicit TLS).
	TLSOn
	// TLSAuto runs a TLS handshake only if the client opens with a TLS
	// handshake record; any other client gets the plaintext handler.
	TLSAuto
)

// UnmarshalYAML accepts tls: true, tls: false, or tls: auto.
func (m *TLSMode) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var b bool
	if err := unmarshal(&b); err == nil {
		*m = TLSOff
		if b {
			*m = TLSOn
		}
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		*m = TLSAuto
	case "true", "on":
		*m = TLSOn
	case "false", "off", "":
		*m = TLSOff
	default:
		return fmt.Errorf("invalid tls mode %q: want true, false or auto", s)
	}
	return nil
}

type ProxyTarget struct {
	Host        string
	Port        uint16
	DialAddress string
}

func (r *Rule) String() string {
	return fmt.Sprintf("Rule: %s", r.Match)
}

func Init(file io.Reader) (Rules, error) {
	config := &Config{}
	if err := yaml.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	if err := config.Rules.init(); err != nil {
		return nil, err
	}
	return config.Rules, nil
}

func (rule *Rule) init(idx int) error {
	if rule.isInit {
		return nil
	}

	switch rule.Type {
	case "conn_handler":
		rule.RuleType = UserConnHandler
	case "proxy_tcp":
		rule.RuleType = ProxyTCP
	case "proxy_udp":
		rule.RuleType = ProxyUDP
	case "drop":
		rule.RuleType = Drop
	default:
		return fmt.Errorf("unknown rule type: %s", rule.Type)
	}

	if rule.TLS != TLSOff && rule.RuleType != UserConnHandler {
		return fmt.Errorf("tls is only supported on conn_handler rules, not %s", rule.Type)
	}

	if rule.RuleType == ProxyTCP || rule.RuleType == ProxyUDP {
		target, err := parseProxyTarget(rule.Target)
		if err != nil {
			return fmt.Errorf("invalid %s target: %w", rule.Type, err)
		}
		rule.ProxyTarget = target
	}

	var err error
	if len(rule.Match) > 0 {
		rule.matcher, err = compileMatcher(rule.Match)
		if err != nil {
			return err
		}
	}

	rule.index = idx
	rule.isInit = true

	return nil
}

// compileMatcher compiles a pcap filter expression with libpcap (once, at
// init) and loads the program into a pure-Go BPF VM for matching.
func compileMatcher(expr string) (*bpf.VM, error) {
	ins, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expr)
	if err != nil {
		return nil, err
	}
	raw := make([]bpf.RawInstruction, len(ins))
	for i, in := range ins {
		raw[i] = bpf.RawInstruction{Op: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	filter, ok := bpf.Disassemble(raw)
	if !ok {
		return nil, fmt.Errorf("filter %q uses BPF instructions the Go VM cannot run", expr)
	}
	vm, err := bpf.NewVM(filter)
	if err != nil {
		return nil, fmt.Errorf("filter %q: %w", expr, err)
	}
	return vm, nil
}

// matches reports whether the rule's filter accepts the packet.
func (r *Rule) matches(packet []byte) bool {
	n, err := r.matcher.Run(packet)
	return err == nil && n > 0
}

func parseProxyTarget(raw string) (*ProxyTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target is required")
	}

	host, portValue, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("host is required")
	}

	port, err := strconv.Atoi(portValue)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portValue, err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}

	return &ProxyTarget{
		Host:        host,
		Port:        uint16(port),
		DialAddress: net.JoinHostPort(host, strconv.Itoa(port)),
	}, nil
}

// maxFakePacket is the largest header-only packet fakePacket builds:
// Ethernet (14) + IPv6 (40) + TCP (20).
const maxFakePacket = 14 + 40 + 20

// addrPort extracts the IP and port of a TCP or UDP address. IPv4-mapped IPv6
// addresses are unmapped so they match IPv4 filters.
func addrPort(a net.Addr) (netip.AddrPort, error) {
	var ap netip.AddrPort
	switch a := a.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.AddrPort{}, err
		}
	}
	if !ap.Addr().IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid address %q", a.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// fakePacket writes into buf the headers of a packet that src would send to
// dst over network ("tcp" or "udp") and returns the written part of buf.
// Only what the rule filters look at is filled in: an Ethernet header, an
// IPv4 or IPv6 header (picked by the address family) and the ports. Checksums
// stay zero because the filters never inspect them.
func fakePacket(buf *[maxFakePacket]byte, network string, src, dst netip.AddrPort) ([]byte, error) {
	var proto byte
	transportLen := 0
	switch network {
	case "tcp":
		proto, transportLen = 6, 20
	case "udp":
		proto, transportLen = 17, 8
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return nil, fmt.Errorf("address family mismatch: %s -> %s", src, dst)
	}

	*buf = [maxFakePacket]byte{}
	// Ethernet: broadcast destination, fixed source MAC.
	copy(buf[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(buf[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	var ipLen int
	if src.Addr().Is4() {
		ipLen = 20
		binary.BigEndian.PutUint16(buf[12:], 0x0800)
		ip := buf[14 : 14+ipLen]
		ip[0] = 0x45 // version 4, IHL 5
		binary.BigEndian.PutUint16(ip[2:], uint16(ipLen+transportLen))
		ip[8] = 64 // TTL
		ip[9] = proto
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(ip[12:16], s[:])
		copy(ip[16:20], d[:])
	} else {
		ipLen = 40
		binary.BigEndian.PutUint16(buf[12:], 0x86dd)
		ip := buf[14 : 14+ipLen]
		ip[0] = 0x60 // version 6
		binary.BigEndian.PutUint16(ip[4:], uint16(transportLen))
		ip[6] = proto // next header
		ip[7] = 64    // hop limit
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(ip[8:24], s[:])
		copy(ip[24:40], d[:])
	}

	th := buf[14+ipLen : 14+ipLen+transportLen]
	binary.BigEndian.PutUint16(th[0:], src.Port())
	binary.BigEndian.PutUint16(th[2:], dst.Port())
	if proto == 6 {
		th[12] = 5 << 4 // data offset: 5 words
	} else {
		binary.BigEndian.PutUint16(th[4:], uint16(transportLen))
	}
	return buf[:14+ipLen+transportLen], nil
}

type Rules []*Rule

// Match returns the first rule whose filter accepts a packet from srcAddr to
// dstAddr over network ("tcp" or "udp"), or nil if none does.
func (rs Rules) Match(network string, srcAddr, dstAddr net.Addr) (*Rule, error) {
	src, err := addrPort(srcAddr)
	if err != nil {
		return nil, err
	}
	dst, err := addrPort(dstAddr)
	if err != nil {
		return nil, err
	}
	var buf [maxFakePacket]byte
	b, err := fakePacket(&buf, network, src, dst)
	if err != nil {
		return nil, fmt.Errorf("failed to fake packet: %w", err)
	}

	for _, rule := range rs {
		if rule.matcher != nil && rule.matches(b) {
			return rule, nil
		}
	}

	return nil, nil
}

// Init initializes the rules
func (rs Rules) init() error {
	for i, rule := range rs {
		if err := rule.init(i); err != nil {
			return err
		}
		rs[i] = rule
	}
	return nil
}
