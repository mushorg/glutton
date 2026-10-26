package glutton

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/spf13/viper"
)

// maxMultiportPorts is the most ports one iptables multiport match accepts.
const maxMultiportPorts = 15

// ignoredPorts are excluded from TPROXY redirection.
type ignoredPorts struct {
	// Incoming are destination ports: services on this host (e.g. the management sshd).
	Incoming []uint32
	// Outgoing are source ports: replies from remote services this host connects to (e.g. DNS on 53).
	Outgoing []uint32
	// NoTrack is the management sshd port kept out of conntrack (0 for none), so a full
	// conntrack table cannot drop new SSH connections.
	NoTrack uint32
}

// ignoredPortsFromConfig merges ports.ssh (0 for none) into ports.ignore.incoming and reads ports.ignore.outgoing.
// ports.ssh is also exempted from conntrack unless ports.ssh_notrack is false.
func ignoredPortsFromConfig() (ignoredPorts, error) {
	incoming := viper.GetIntSlice("ports.ignore.incoming")
	ssh := viper.GetInt("ports.ssh")
	if ssh != 0 {
		incoming = append(incoming, ssh)
	}
	in, err := normalizePorts("ports.ignore.incoming", incoming)
	if err != nil {
		return ignoredPorts{}, err
	}
	out, err := normalizePorts("ports.ignore.outgoing", viper.GetIntSlice("ports.ignore.outgoing"))
	if err != nil {
		return ignoredPorts{}, err
	}
	ignore := ignoredPorts{Incoming: in, Outgoing: out}
	if ssh != 0 && (!viper.IsSet("ports.ssh_notrack") || viper.GetBool("ports.ssh_notrack")) {
		ignore.NoTrack = uint32(ssh)
	}
	return ignore, nil
}

// normalizePorts validates, sorts and de-duplicates ports.
func normalizePorts(key string, ports []int) ([]uint32, error) {
	out := make([]uint32, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("%s: invalid port %d", key, p)
		}
		out = append(out, uint32(p))
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxMultiportPorts {
		return nil, fmt.Errorf("%s: %d ports given, iptables multiport accepts at most %d", key, len(out), maxMultiportPorts)
	}
	return out, nil
}

func joinPorts(ports []uint32) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(s, ",")
}

// genRuleSpec builds the TPROXY rule, e.g.
// iptables -t mangle -A PREROUTING -i eth0 -p tcp -m state ! --state ESTABLISHED,RELATED -m multiport ! --dports 22,2222 -m multiport ! --sports 53 -j TPROXY --on-port 5000 --on-ip 127.0.0.1
func genRuleSpec(chain, iface, protocol, _ string, ignore ignoredPorts, dport uint32) []string {
	var spec []string
	switch chain {
	case "PREROUTING":
		spec = append(spec, "-i", iface)
	case "OUTPUT":
		spec = append(spec, "-o", iface)
	}
	spec = append(spec, "-p", protocol, "-m", "state", "!", "--state", "ESTABLISHED,RELATED")
	if len(ignore.Incoming) > 0 {
		spec = append(spec, "-m", "multiport", "!", "--dports", joinPorts(ignore.Incoming))
	}
	if len(ignore.Outgoing) > 0 {
		spec = append(spec, "-m", "multiport", "!", "--sports", joinPorts(ignore.Outgoing))
	}
	return append(spec, "-j", "TPROXY", "--on-port", strconv.FormatUint(uint64(dport), 10), "--on-ip", "127.0.0.1")
}

func setTProxyIPTables(iface, srcIP, protocol string, port uint32, ignore ignoredPorts) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return ipt.AppendUnique("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, protocol, srcIP, ignore, port)...)
}

func flushTProxyIPTables(iface, srcIP, protocol string, port uint32, ignore ignoredPorts) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	return ipt.Delete("mangle", "PREROUTING", genRuleSpec("PREROUTING", iface, protocol, srcIP, ignore, port)...)
}

// genNoTrackSpecs builds the raw table rules that keep TCP port on this host out of conntrack, e.g.
// iptables -t raw -A PREROUTING -i eth0 -p tcp --dport 22 -j CT --notrack
// iptables -t raw -A OUTPUT -o eth0 -p tcp --sport 22 -j CT --notrack
func genNoTrackSpecs(iface string, port uint32) map[string][]string {
	p := strconv.FormatUint(uint64(port), 10)
	return map[string][]string{
		"PREROUTING": {"-i", iface, "-p", "tcp", "--dport", p, "-j", "CT", "--notrack"},
		"OUTPUT":     {"-o", iface, "-p", "tcp", "--sport", p, "-j", "CT", "--notrack"},
	}
}

func setNoTrackIPTables(iface string, ignore ignoredPorts) error {
	if ignore.NoTrack == 0 {
		return nil
	}
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	for chain, spec := range genNoTrackSpecs(iface, ignore.NoTrack) {
		if err := ipt.AppendUnique("raw", chain, spec...); err != nil {
			return err
		}
	}
	return nil
}

func flushNoTrackIPTables(iface string, ignore ignoredPorts) error {
	if ignore.NoTrack == 0 {
		return nil
	}
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	var errs []error
	for chain, spec := range genNoTrackSpecs(iface, ignore.NoTrack) {
		if err := ipt.DeleteIfExists("raw", chain, spec...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
