package glutton

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// iptables -t mangle -I PREROUTING -d 192.0.2.0/24 -p tcp -j TPROXY --on-port 5000 --on-ip 127.0.0.1
func setTProxyIPTables(device string, port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	_, err = ipt.List("mangle", "PREROUTING")
	if err != nil {
		return err
	}

	return ipt.Append("mangle", "PREROUTING", strings.Split("-i ens2 -p tcp ! --dport 22 -j TPROXY --on-port 5000 --on-ip 127.0.0.1", " ")...)
}
