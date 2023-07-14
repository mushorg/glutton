package rules

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	yaml "gopkg.in/yaml.v2"
)

type RuleType int

const (
	Rewrite RuleType = iota
	ProxyTCP
	LogTCP
	LogHTTP
	UserConnHandler
	Drop
	PassThrough
)

type Config struct {
	Version int     `yaml:"version"`
	Rules   []*Rule `yaml:"rules"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Type   string `yaml:"type"`
	Target string `yaml:"target,omitempty"`
	Name   string `yaml:"name,omitempty"`

	isInit    bool
	ruleType  RuleType
	index     int
	matcher   *pcap.BPF
	targetURL *url.URL

	host string
	port int
}

func (r *Rule) String() string {
	return fmt.Sprintf("Rule: %s", r.Match)
}

func ParseRuleSpec(file *os.File) (Rules, error) {
	config := &Config{}
	if err := yaml.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}

	if config.Version == 0 {
		// TODO: log warning
		config.Version = 1
	}

	if config.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version: %v", config.Version)
	}

	return config.Rules, nil
}

func InitRule(idx int, rule *Rule) error {
	if rule.isInit {
		return nil
	}

	switch rule.Type {
	case "rewrite":
		rule.ruleType = Rewrite
	case "proxy":
		rule.ruleType = ProxyTCP
	case "log_tcp":
		rule.ruleType = LogTCP
	case "log_http":
		rule.ruleType = LogHTTP
	case "conn_handler":
		rule.ruleType = UserConnHandler
	case "drop":
		rule.ruleType = Drop
	case "passthrough":
		rule.ruleType = PassThrough
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

	if rule.Target != "" {
		var err error
		if rule.ruleType == ProxyTCP {
			rule.targetURL, err = url.Parse(rule.Target)
			if err != nil {
				return err
			}

			var sport string
			rule.host, sport, err = net.SplitHostPort(rule.targetURL.Host)
			if err != nil {
				return err
			}

			rule.port, err = strconv.Atoi(sport)
			if err != nil {
				return err
			}

			// TODO: handle scheme specific validation/parsing
		}

		if rule.ruleType == Rewrite {
			rule.port, err = strconv.Atoi(rule.Target)
			if err != nil {
				return err
			}
		}
	}

	rule.index = idx
	rule.isInit = true

	return nil
}

func splitAddr(addr string) (net.IP, layers.TCPPort, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	sIP := net.ParseIP(ip)

	dPort, err := strconv.Atoi(port)
	if err != nil {
		return nil, 0, err
	}
	return sIP, layers.TCPPort(dPort), nil
}

func fakePacketBytes(conn net.Conn) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	sIP, sPort, err := splitAddr(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dIP, dPort, err := splitAddr(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP: sIP,
		DstIP: dIP,
	}
	tcp := &layers.TCP{
		SrcPort: sPort,
		DstPort: dPort,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		return nil, err
	}

	if err := gopacket.SerializeLayers(buf, opts,
		eth,
		ipv4,
		tcp,
		gopacket.Payload([]byte{})); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type Rules []*Rule

func (rs Rules) Match(conn net.Conn) (*Rule, error) {
	b, err := fakePacketBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to fake packet: %w", err)
	}

	println("packet bytes len:", len(b))

	for _, rule := range rs {
		if rule.matcher != nil {
			n := len(b)
			if rule.matcher.Matches(gopacket.CaptureInfo{
				CaptureLength: n,
				Length:        n,
				Timestamp:     time.Now(),
			}, b) {
				return rule, nil
			}
		}
	}

	return nil, nil
}
