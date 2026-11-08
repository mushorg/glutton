package rules

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testFlow(network, src, dst string) *flow {
	f := &flow{proto: protoTCP, src: netip.MustParseAddrPort(src), dst: netip.MustParseAddrPort(dst)}
	if network == "udp" {
		f.proto = protoUDP
	}
	return f
}

func TestCompileFilter(t *testing.T) {
	for _, tc := range []struct {
		expr     string
		network  string
		src, dst string
		want     bool
	}{
		{"tcp", "tcp", "192.0.2.1:50000", "192.0.2.10:1", true},
		{"tcp", "udp", "192.0.2.1:50000", "192.0.2.10:1", false},
		{"icmp", "tcp", "192.0.2.1:50000", "192.0.2.10:1", false},
		{"ip", "tcp", "[2001:db8::1]:1", "[2001:db8::2]:2", false},
		{"ip6", "tcp", "[2001:db8::1]:1", "[2001:db8::2]:2", true},
		{"tcp dst port 23", "tcp", "192.0.2.1:50000", "192.0.2.10:23", true},
		{"tcp dst port 23", "tcp", "192.0.2.1:23", "192.0.2.10:50000", false},
		{"tcp dst port 23", "udp", "192.0.2.1:50000", "192.0.2.10:23", false},
		// A bare number inherits "tcp dst port".
		{"tcp dst port 23 or 2323", "tcp", "192.0.2.1:50000", "192.0.2.10:2323", true},
		{"tcp dst port 23 or 2323", "tcp", "192.0.2.1:2323", "192.0.2.10:50000", false},
		{"tcp dst port 23 or 2323", "udp", "192.0.2.1:50000", "192.0.2.10:2323", false},
		// A bare "port" matches either protocol and direction.
		{"tcp dst port 23 or port 2323", "udp", "192.0.2.1:2323", "192.0.2.10:1", true},
		// and/or group left to right: (port 80 or port 81) and udp.
		{"port 80 or 81 and udp", "tcp", "192.0.2.1:1", "192.0.2.10:80", false},
		// "not" is not inherited: (not port 80) or port 81.
		{"not port 80 or 81", "tcp", "192.0.2.1:1", "192.0.2.10:81", true},
		{"not port 80 or 81", "tcp", "192.0.2.1:1", "192.0.2.10:80", false},
		{"port 010", "tcp", "192.0.2.1:1", "192.0.2.10:8", true},
		{"port 0x50", "tcp", "192.0.2.1:1", "192.0.2.10:80", true},
		{"tcp dst portrange 5900-5910", "tcp", "192.0.2.1:1", "192.0.2.10:5905", true},
		{"tcp dst portrange 5910-5900", "tcp", "192.0.2.1:1", "192.0.2.10:5900", true},
		{"tcp dst portrange 5900-5910", "tcp", "192.0.2.1:1", "192.0.2.10:5911", false},
		{"src and dst port 80", "tcp", "192.0.2.1:80", "192.0.2.10:81", false},
		{"src or dst port 80", "tcp", "192.0.2.1:80", "192.0.2.10:81", true},
		{"src net 10.0.0.0/8", "tcp", "10.1.2.3:1", "192.0.2.10:1", true},
		{"src net 10.0.0.0/8", "tcp", "192.0.2.10:1", "10.1.2.3:1", false},
		{"host 192.0.2.1 or 192.0.2.9", "tcp", "192.0.2.9:1", "192.0.2.10:1", true},
		{"ip6 net 2001:db8::/32", "udp", "[2001:db8::1]:1", "[2001:db9::1]:1", true},
		{"(tcp or udp) and port 53", "udp", "192.0.2.1:1", "192.0.2.10:53", true},
		{"not (tcp and port 80)", "tcp", "192.0.2.1:1", "192.0.2.10:80", false},
	} {
		t.Run(tc.expr+" "+tc.network+" "+tc.src+"->"+tc.dst, func(t *testing.T) {
			m, err := compileFilter(tc.expr)
			require.NoError(t, err)
			require.Equal(t, tc.want, m.match(testFlow(tc.network, tc.src, tc.dst)))
		})
	}
}

func TestCompileFilterErrors(t *testing.T) {
	for expr, want := range map[string]string{
		"":                             "empty",
		"tcp dst port nope":            "port names are not supported",
		"port http":                    "port names are not supported",
		"port 65536":                   "> 65535",
		"port 080":                     "invalid port",
		"host localhost":               "host names",
		"net 10.1":                     "partial addresses",
		"net 10.0.0.1/8":               "non-network bits",
		"ip port 80":                   "illegal qualifier",
		"tcp host 192.0.2.1":           "modifier applied to host",
		"ip6 host 192.0.2.1":           "modifier applied to host",
		"ip net 2001:db8::/32":         "modifier applied to net",
		"80":                           "needs a qualifier",
		"tcp or 80":                    "needs a qualifier",
		"port 80 or src 81":            "want an IP address",
		"tcp[13] & 2 != 0":             "unsupported",
		"len <= 100":                   "unsupported",
		"ether host 00:11:22:33:44:55": "unsupported filter keyword",
		"vlan":                         "unsupported filter keyword",
		"tcp and":                      "unexpected end",
		"(tcp":                         "missing ')'",
		"(port 1) or 2":                "needs a qualifier",
		"tcp)":                         "syntax error",
		"ip 192.0.2.1":                 "syntax error",
		"icmp port 80":                 "syntax error",
		"tcp dst port":                 "missing value",
		"tcp dst port (80)":            "unsupported value",
	} {
		_, err := compileFilter(expr)
		require.Error(t, err, "%q", expr)
		require.Contains(t, err.Error(), want, "%q", expr)
	}
}

func TestInitRejectsUnsupportedMatch(t *testing.T) {
	_, err := Init(strings.NewReader("rules:\n  - match: tcp dst port http\n    type: conn_handler\n    target: http\n"))
	require.ErrorContains(t, err, `invalid match "tcp dst port http"`)
}

func TestMatchErrors(t *testing.T) {
	rs := parseRules(t)
	v4 := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	v6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	_, err := rs.Match("sctp", v4, v4)
	require.ErrorContains(t, err, "unsupported network")
	_, err = rs.Match("tcp", v4, v6)
	require.ErrorContains(t, err, "address family mismatch")
}

// TestMatchIgnoresZone checks that a link-local peer with a zone still
// matches a host filter on its address.
func TestMatchIgnoresZone(t *testing.T) {
	rs, err := Init(strings.NewReader("rules:\n  - match: tcp and src host fe80::1\n    type: conn_handler\n    target: tcp\n"))
	require.NoError(t, err)
	src := &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1, Zone: "eth0"}
	dst := &net.TCPAddr{IP: net.ParseIP("fe80::2"), Port: 2, Zone: "eth0"}
	match, err := rs.Match("tcp", src, dst)
	require.NoError(t, err)
	require.NotNil(t, match)
}
