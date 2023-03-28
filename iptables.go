package glutton

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// iptables -t mangle -I PREROUTING -d 192.0.2.0/24 -p tcp -j TPROXY --on-port=1234 --on-ip=127.0.0.1
func setTProxyIPTables(port uint32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	_, err = ipt.List("mangle", "PREROUTING")
	if err != nil {
		return err
	}

	return ipt.Append("mangle", "PREROUTING", strings.Split("-p tcp -j TPROXY --on-port=5000 --on-ip=127.0.0.1", " ")...)
}
