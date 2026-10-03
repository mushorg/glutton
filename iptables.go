package glutton

import (
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

type iptablesRedirector struct {
	cfg tproxyRedirect
}

func (r *iptablesRedirector) Apply(cfg tproxyRedirect) error {
	r.cfg = cfg
	if err := setTProxyIPTables(cfg.Interface, "", "tcp", uint32(cfg.TCPPort), uint32(cfg.SSHPort)); err != nil {
		return fmt.Errorf("failed to set TCP TPROXY iptables rule: %w", err)
	}
	if err := setTProxyIPTables(cfg.Interface, "", "udp", uint32(cfg.UDPPort), uint32(cfg.SSHPort)); err != nil {
		return fmt.Errorf("failed to set UDP TPROXY iptables rule: %w", err)
	}
	return nil
}

func (r *iptablesRedirector) Flush() error {
	return errors.Join(
		flushTProxyIPTables(r.cfg.Interface, "", "tcp", uint32(r.cfg.TCPPort), uint32(r.cfg.SSHPort)),
		flushTProxyIPTables(r.cfg.Interface, "", "udp", uint32(r.cfg.UDPPort), uint32(r.cfg.SSHPort)),
	)
}

var (
	// iptables -t mangle -I PREROUTING -p tcp ! --dport 22 -m state ! --state ESTABLISHED,RELATED -j TPROXY --on-port 5000 --on-ip 127.0.0.1
	specTCP = "-p;%s;-m;state;!;--state;ESTABLISHED,RELATED;!;--dport;%d;-j;TPROXY;--on-port;%d;--on-ip;127.0.0.1"
	specUDP = "-p;%s;-m;state;!;--state;ESTABLISHED,RELATED;!;--dport;%d;-j;TPROXY;--on-port;%d;--on-ip;127.0.0.1"
)

func genRuleSpec(chain, iface, protocol, _ string, sshPort, dport uint32) []string {
	var spec string
	switch protocol {
	case "udp":
		spec = specUDP
	case "tcp":
		spec = specTCP
	}
	switch chain {
	case "PREROUTING":
		spec = "-i;%s;" + spec
	case "OUTPUT":
		spec = "-o;%s;" + spec
	}
	return strings.Split(fmt.Sprintf(spec, iface, protocol, sshPort, dport), ";")
}

func setTProxyIPTables(iface, srcIP, protocol string, port, sshPort uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return ipt.AppendUnique("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, protocol, srcIP, sshPort, port)...)
}

func flushTProxyIPTables(iface, srcIP, protocol string, port, sshPort uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	return ipt.Delete("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, protocol, srcIP, sshPort, port)...)
}
