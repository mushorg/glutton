package glutton

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

func genRuleSpec(chain, iface, protocol, srcIP string, sshPort, dport uint32) []string {
	// iptables -t mangle -I PREROUTING -p tcp ! --dport 22 -m state ! --state ESTABLISHED,RELATED -j TPROXY --on-port 5000 --on-ip 127.0.0.1
	spec := "-p;%s;-m;state;!;--state;ESTABLISHED,RELATED;!;--dport;%d;-j;TPROXY;--on-port;%d;--on-ip;127.0.0.1"
	switch chain {
	case "PREROUTING":
		spec = "-i;%s;" + spec
	case "OUTPUT":
		spec = "-o;%s;" + spec
	}
	return strings.Split(fmt.Sprintf(spec, iface, protocol, sshPort, dport), ";")
}

func setTProxyIPTables(iface, srcIP string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return ipt.AppendUnique("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", srcIP, 22, port)...)
}

func flushTProxyIPTables(iface, srcIP string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	return ipt.Delete("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", srcIP, 22, port)...)
}
