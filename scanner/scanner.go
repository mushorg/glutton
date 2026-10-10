package scanner

import (
	"net"
	"strings"
)

var (
	scannerSubnet = map[string][]string{
		"censys": {
			"162.142.125.0/24",
			"167.94.138.0/24",
			"167.94.145.0/24",
			"167.94.146.0/24",
			"167.248.133.0/24",
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
		"rwth": {
			"137.226.113.56/26",
		},
	}
)

// Classify reports a known scanner label (if any) and the first PTR name.
// CIDR matches do not trigger DNS. PTR lookup runs only when the IP is not
// in a known scanner prefix, matching IsScanner.
func Classify(ip net.IP) (scannerName, srcPtr string, err error) {
	if ip == nil {
		return "", "", nil
	}
	for scanner, subnets := range scannerSubnet {
		for _, subnet := range subnets {
			_, network, err := net.ParseCIDR(subnet)
			if err != nil {
				return "", "", err
			}
			if network.Contains(ip) {
				return scanner, "", nil
			}
		}
	}
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return "", "", nil
	}
	if len(names) > 0 {
		srcPtr = strings.TrimSuffix(names[0], ".")
	}
	for _, name := range names {
		if strings.HasSuffix(name, "shodan.io.") {
			return "shodan", srcPtr, nil
		}
		if strings.HasSuffix(name, "binaryedge.ninja.") {
			return "binaryedge", srcPtr, nil
		}
		if strings.HasSuffix(name, "rwth-aachen.de.") {
			return "rwth", srcPtr, nil
		}
		if strings.HasSuffix(name, "shadowserver.io.") {
			return "shadowserver", srcPtr, nil
		}
		if strings.HasSuffix(name, "censys.io.") {
			return "censys", srcPtr, nil
		}
		if strings.HasSuffix(name, "infrawat.ch") {
			return "infrawat", srcPtr, nil
		}
	}
	return "", srcPtr, nil
}

func IsScanner(ip net.IP) (bool, string, error) {
	name, _, err := Classify(ip)
	if err != nil {
		return false, "", err
	}
	return name != "", name, nil
}
