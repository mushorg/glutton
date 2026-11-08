package glutton

import (
	"fmt"
	"net"
)

func getNonLoopbackIPs(ifaceName string) ([]net.IP, error) {
	nonLoopback := []net.IP{}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nonLoopback, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nonLoopback, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			nonLoopback = append(nonLoopback, ipNet.IP)
		}
	}

	if len(nonLoopback) == 0 {
		return nonLoopback, fmt.Errorf("unable to find any non-loopback addresses for: %s", ifaceName)
	}

	return nonLoopback, nil
}
