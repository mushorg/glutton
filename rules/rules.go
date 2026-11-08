package rules

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

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
	// filter is the compiled Match expression. It is stateless, so the TCP
	// and UDP listeners can match concurrently.
	filter *matcher
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

	if len(rule.Match) > 0 {
		filter, err := compileFilter(rule.Match)
		if err != nil {
			return fmt.Errorf("invalid match %q: %w", rule.Match, err)
		}
		rule.filter = filter
	}

	rule.index = idx
	rule.isInit = true

	return nil
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

// addrPort extracts the IP and port of a TCP or UDP address. IPv4-mapped IPv6
// addresses are unmapped so they match IPv4 filters, and zones are dropped
// because a filter matches on the address bytes alone.
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
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), nil
}

type Rules []*Rule

// Match returns the first rule whose filter accepts a flow from srcAddr to
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
	f := flow{src: src, dst: dst}
	switch network {
	case "tcp":
		f.proto = protoTCP
	case "udp":
		f.proto = protoUDP
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return nil, fmt.Errorf("address family mismatch: %s -> %s", src, dst)
	}

	for _, rule := range rs {
		if rule.filter != nil && rule.filter.match(&f) {
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
