package glutton

import (
	"net"
	"strings"
)

var (
	scannerSubnet = map[string][]string{
		"censys": {
			"162.142.125.0/24",
			"167.94.138.0/24",
			"167.248.133.0/24",
			"192.35.168.0/23",
		},
		"shadowserver": {
			"64.62.202.96/27",
			"66.220.23.112/29",
			"74.82.47.0/26",
			"184.105.139.64/26",
			"184.105.143.128/26",
			"184.105.247.192/26",
			"216.218.206.64/26",
			"141.212.0.0/16",
		},
		"PAN Expanse": {
			"144.86.173.0/24",
		},
	}
)

func isShodan(ip net.IP) (bool, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if strings.HasSuffix(name, "shodan.io.") {
			return true, nil
		}
	}
	return false, nil
}

func isScanner(ip net.IP) (bool, string, error) {
	for scanner, subnets := range scannerSubnet {
		for _, subnet := range subnets {
			_, net, err := net.ParseCIDR(subnet)
			if err != nil {
				return false, "", err
			}
			if net.Contains(ip) {
				return true, scanner, nil
			}
		}
	}
	ok, err := isShodan(ip)
	if ok && err == nil {
		return true, "shodan", nil
	}
	return false, "", err
}
