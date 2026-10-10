package glutton

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestGenRuleSpec(t *testing.T) {
	spec := genRuleSpec("PREROUTING", "eth0", "tcp", "1.2.3.4", ignoredPorts{Incoming: []uint32{22, 2222}, Outgoing: []uint32{53}}, 5000)
	require.Equal(t, "-i eth0 -p tcp -m state ! --state ESTABLISHED,RELATED -m multiport ! --dports 22,2222 -m multiport ! --sports 53 -j TPROXY --on-port 5000 --on-ip 127.0.0.1", strings.Join(spec, " "))

	spec = genRuleSpec("PREROUTING", "eth0", "udp", "1.2.3.4", ignoredPorts{Incoming: []uint32{22}}, 5001)
	require.Equal(t, "-i eth0 -p udp -m state ! --state ESTABLISHED,RELATED -m multiport ! --dports 22 -j TPROXY --on-port 5001 --on-ip 127.0.0.1", strings.Join(spec, " "))

	spec = genRuleSpec("PREROUTING", "eth0", "tcp", "1.2.3.4", ignoredPorts{}, 5000)
	require.Equal(t, "-i eth0 -p tcp -m state ! --state ESTABLISHED,RELATED -j TPROXY --on-port 5000 --on-ip 127.0.0.1", strings.Join(spec, " "))
}

func TestIgnoredPortsFromConfig(t *testing.T) {
	keys := []string{"ports.ssh", "ports.ignore.incoming", "ports.ignore.outgoing"}
	orig := map[string]any{}
	for _, k := range keys {
		orig[k] = viper.Get(k)
	}
	t.Cleanup(func() {
		for k, v := range orig {
			viper.Set(k, v)
		}
	})
	set := func(ssh any, in, out []int) {
		viper.Set("ports.ssh", ssh)
		viper.Set("ports.ignore.incoming", in)
		viper.Set("ports.ignore.outgoing", out)
	}

	set(22, []int{2222, 22, 8022}, []int{53, 123})
	got, err := ignoredPortsFromConfig()
	require.NoError(t, err)
	require.Equal(t, ignoredPorts{Incoming: []uint32{22, 2222, 8022}, Outgoing: []uint32{53, 123}}, got, "ssh merged, sorted, de-duplicated")

	set(0, nil, nil)
	got, err = ignoredPortsFromConfig()
	require.NoError(t, err)
	require.Empty(t, got.Incoming)
	require.Empty(t, got.Outgoing)

	set(22, []int{0}, nil)
	_, err = ignoredPortsFromConfig()
	require.ErrorContains(t, err, "invalid port 0")

	set(0, nil, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	_, err = ignoredPortsFromConfig()
	require.ErrorContains(t, err, "at most 15")
}
