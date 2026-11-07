package glutton

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

func getNonLoopbackIPs(ifaceName string) ([]net.IP, error) {
	nonLoopback := []net.IP{}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nonLoopback, err
	}

	for _, iface := range ifs {
		if strings.EqualFold(iface.Name, ifaceName) {
			for _, addr := range iface.Addresses {
				if !addr.IP.IsLoopback() && addr.IP.To4() != nil {
					nonLoopback = append(nonLoopback, addr.IP)
				}
			}
		}
	}

	if len(nonLoopback) == 0 {
		return nonLoopback, fmt.Errorf("unable to find any non-loopback addresses for: %s", ifaceName)
	}

	return nonLoopback, nil
}
