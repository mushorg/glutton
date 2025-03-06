package rules

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	yaml "gopkg.in/yaml.v2"
)

type RuleType int

const (
	UserConnHandler RuleType = iota
	Drop
	PassThrough
)

type Config struct {
	Version int   `yaml:"version"`
	Rules   Rules `yaml:"rules"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Type   string `yaml:"type"`
	Target string `yaml:"target,omitempty"`
	Name   string `yaml:"name,omitempty"`

	isInit   bool
	RuleType RuleType
	index    int
	matcher  *pcap.BPF
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
	case "drop":
		rule.RuleType = Drop
	case "pass_through":
		rule.RuleType = PassThrough
	default:
		return fmt.Errorf("unknown rule type: %s", rule.Type)
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
