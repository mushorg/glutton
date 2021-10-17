package glutton

import (
	"log"
	"net"
)

var (
	censys = []string{
		"162.142.125.0/24",
		"167.94.138.0/24",
		"167.248.133.0/24",
		"192.35.168.0/23",
	}
	shadowserver = []string{
		"64.62.202.96/27",
		"66.220.23.112/29",
		"74.82.47.0/26",
		"184.105.139.64/26",
		"184.105.143.128/26",
		"184.105.247.192/26",
		"216.218.206.64/26",
		"141.212.0.0/16",
	}
)

func isScanner(ip net.IP) bool {
	for _, subnet := range append(censys, shadowserver...) {
		_, net, err := net.ParseCIDR(subnet)
		if err != nil {
			log.Fatalf("invalid subnet: %v", err)
			continue
		}
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
