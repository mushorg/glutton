package rules

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	matcher     *pcap.BPF
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
		rule.matcher, err = pcap.NewBPF(layers.LinkTypeEthernet, 65535, rule.Match)
		if err != nil {
			return err
		}
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

func splitAddr(addr string) (string, uint16, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	dPort, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	return ip, uint16(dPort), nil
}

func fakePacketBytes(network, srcIP, dstIP string, srcPort, dstPort uint16) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x0, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
		Version: 4,
	}

	var transport gopacket.SerializableLayer
	switch network {
	case "tcp":
		ipv4.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
			return nil, err
		}
		transport = tcp

	case "udp":
		ipv4.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
			return nil, err
		}
		transport = udp
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	},
		eth,
		ipv4,
		transport,
		gopacket.Payload([]byte{})); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type Rules []*Rule

func (rs Rules) Match(network string, srcAddr, dstAddr net.Addr) (*Rule, error) {
	srcIP, srcPort, err := splitAddr(srcAddr.String())
	if err != nil {
		return nil, err
	}
	dstIP, dstPort, err := splitAddr(dstAddr.String())
	if err != nil {
		return nil, err
	}
	b, err := fakePacketBytes(network, srcIP, dstIP, srcPort, dstPort)
	if err != nil {
		return nil, fmt.Errorf("failed to fake packet: %w", err)
	}

	for _, rule := range rs {
		if rule.matcher != nil {
			n := len(b)
			if rule.matcher.Matches(gopacket.CaptureInfo{
				InterfaceIndex: 0,
				CaptureLength:  n,
				Length:         n,
				Timestamp:      time.Now(),
			}, b) {
				return rule, nil
			}
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
