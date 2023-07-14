package glutton

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

func genRuleSpec(chain, iface, protocol, srcIP string, sshPort, dport uint32) []string {
	spec := "-p,%s,!,-s,%s,!,--dport,%d,-j,TPROXY,--on-port,%d,--on-ip,127.0.0.1" //,--tproxy-mark,1/1"
	switch chain {
	case "PREROUTING":
		spec = "-i,%s," + spec
	case "OUTPUT":
		spec = "-o,%s," + spec
	}
	return strings.Split(fmt.Sprintf(spec, iface, protocol, srcIP, sshPort, dport), ",")
}

// iptables -t mangle -I PREROUTING -p tcp !-s eth0 !--dport 22 -j TPROXY --on-port 5000 --on-ip 127.0.0.1
// echo "10 tproxy" >> /etc/iproute2/rt_tables
// ip rule add from 10.64.70.81 table tproxy
func setTProxyIPTables(iface, srcIP string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	// if err := ipt.AppendUnique("mangle", "OUTPUT", strings.Split("iptables -I OUTPUT -o ens2 -d 0.0.0.0/0 -j ACCEPT", " ")...); err != nil {
	// 	return err
	// }
	return ipt.AppendUnique("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", srcIP, 22, port)...)
}

func flushTProxyIPTables(iface, srcIP string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	return ipt.Delete("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, "tcp", srcIP, 22, port)...)
}
