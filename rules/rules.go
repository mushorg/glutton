package rules

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"

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

func ReadRulesFromFile(file *os.File) ([]*Rule, error) {
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return ParseRuleSpec(data)
}

func ParseRuleSpec(spec []byte) ([]*Rule, error) {
	config := &Config{}
	err := yaml.Unmarshal(spec, config)

	if err != nil {
		return nil, err
	}

	if config.Version == 0 {
		// TODO: log warning
		config.Version = 1
	}

	if config.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version: %v", config.Version)
	}

	return config.Rules, err
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

func (r *Rule) RunMatch(d []byte) (*Rule, error) {
	if r.matcher != nil {
		n := len(d)
		if r.matcher.Matches(gopacket.CaptureInfo{CaptureLength: n, Length: n}, d) {
			return r, nil
		}
	}
	return nil, nil
}
