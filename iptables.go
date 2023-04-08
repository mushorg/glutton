package glutton

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

func genRuleSpec(chain, iface, protocol string, sshPort, dport uint32) []string {
	spec := "-p,%s,!,--dport,%d,-j,TPROXY,--on-port,%d,--on-ip,127.0.0.1"
	switch chain {
	case "PREROUTING":
		spec = "-i,%s," + spec
	case "OUTPUT":
		spec = "-o,%s," + spec
	}
	return strings.Split(fmt.Sprintf(spec, iface, protocol, sshPort, dport), ",")
}

// iptables -t mangle -I PREROUTING -i eth0 -p tcp -j TPROXY --on-port 5000 --on-ip 127.0.0.1
func setTProxyIPTables(iface string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	// if err := ipt.AppendUnique("mangle", "OUTPUT", strings.Split("iptables -I OUTPUT -o ens2 -d 0.0.0.0/0 -j ACCEPT", " ")...); err != nil {
	// 	return err
	// }
	return ipt.AppendUnique("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", 22, port)...)
}

func flushTProxyIPTables(iface string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	return ipt.Delete("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", 22, port)...)
}
