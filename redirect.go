package glutton

import "fmt"

type tproxyRedirector interface {
	Apply(cfg tproxyRedirect) error
	Flush() error
}

type tproxyRedirect struct {
	Interface string
	SSHPort   uint16
	TCPPort   uint16
	UDPPort   uint16
}

const (
	redirectorIPTables = "iptables"
	redirectorNFTables = "nftables"
)

func newTProxyRedirector(backend string) (tproxyRedirector, error) {
	switch backend {
	case "", redirectorIPTables:
		return &iptablesRedirector{}, nil
	case redirectorNFTables:
		return newNFTablesRedirector()
	default:
		return nil, fmt.Errorf("unknown redirector %q (want iptables or nftables)", backend)
	}
}
