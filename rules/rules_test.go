package rules

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

func parseRules(t *testing.T) Rules {
	fh, err := os.Open("test.yaml")
	require.NoError(t, err)
	rules, err := Init(fh)
	require.NoError(t, err)
	return rules
}

func TestParseRuleSpec(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
}

func TestInitRule(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)

	for _, rule := range rules {
		require.True(t, rule.isInit)
		require.NotNil(t, rule.matcher)
		require.NotEmpty(t, rule.Type)
	}
}

func TestParseProxyTarget(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantAddress string
		wantErr     string
	}{
		{
			name:        "plain target",
			raw:         "127.0.0.1:9889",
			wantAddress: "127.0.0.1:9889",
		},
		{
			name:        "hostname target",
			raw:         "localhost:9889",
			wantAddress: "localhost:9889",
		},
		{
			name:    "empty target",
			raw:     "",
			wantErr: "target is required",
		},
		{
			name:    "scheme not supported",
			raw:     "tcp://127.0.0.1:9889",
			wantErr: "too many colons",
		},
		{
			name:    "missing port",
			raw:     "127.0.0.1",
			wantErr: "missing port",
		},
		{
			name:    "missing host",
			raw:     ":9889",
			wantErr: "host is required",
		},
		{
			name:    "non numeric port",
			raw:     "127.0.0.1:http",
			wantErr: "invalid port",
		},
		{
			name:    "port out of range",
			raw:     "127.0.0.1:70000",
			wantErr: "port out of range",
		},
		{
			name:    "path not supported",
			raw:     "127.0.0.1:9889/path",
			wantErr: "invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := parseProxyTarget(tt.raw)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantAddress, target.DialAddress)
		})
	}
}

func TestInitProxyTCPRuleParsesTarget(t *testing.T) {
	rules, err := Init(strings.NewReader(`rules:
  - match: tcp dst port 9889
    type: proxy_tcp
    target: 127.0.0.1:9889
`))
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NotNil(t, rules[0].ProxyTarget)
	require.Equal(t, "127.0.0.1:9889", rules[0].ProxyTarget.DialAddress)
}

func TestInitProxyUDPRuleParsesTarget(t *testing.T) {
	rules, err := Init(strings.NewReader(`rules:
  - match: udp dst port 443
    type: proxy_udp
    target: 127.0.0.1:443
    produce: false
`))
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, ProxyUDP, rules[0].RuleType)
	require.NotNil(t, rules[0].ProxyTarget)
	require.Equal(t, "127.0.0.1:443", rules[0].ProxyTarget.DialAddress)
	require.False(t, rules[0].ShouldProduce())
}

func TestInitProxyUDPRuleRejectsInvalidTarget(t *testing.T) {
	_, err := Init(strings.NewReader(`rules:
  - match: udp dst port 443
    type: proxy_udp
    target: tcp://127.0.0.1:443
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid proxy_udp target")
}

func TestRunMatchProxyUDP(t *testing.T) {
	rules, err := Init(strings.NewReader(`rules:
  - match: udp dst port 443
    type: proxy_udp
    target: 127.0.0.1:443
  - match: udp
    type: conn_handler
    target: udp
`))
	require.NoError(t, err)

	srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	dstAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	match, err := rules.Match("udp", srcAddr, dstAddr)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "proxy_udp", match.Type)
	require.NotNil(t, match.ProxyTarget)
	require.Equal(t, "127.0.0.1:443", match.ProxyTarget.DialAddress)
}

func TestShouldProduce(t *testing.T) {
	require.True(t, (*Rule)(nil).ShouldProduce())
	require.True(t, (&Rule{}).ShouldProduce())

	produceTrue := true
	require.True(t, (&Rule{Produce: &produceTrue}).ShouldProduce())

	produceFalse := false
	require.False(t, (&Rule{Produce: &produceFalse}).ShouldProduce())
}

func TestInitRuleProduceFlag(t *testing.T) {
	rules, err := Init(strings.NewReader(`rules:
  - match: tcp dst port 443
    type: proxy_tcp
    target: 127.0.0.1:443
    produce: false
  - match: tcp dst port 80
    type: proxy_tcp
    target: 127.0.0.1:80
`))
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.False(t, rules[0].ShouldProduce())
	require.NotNil(t, rules[0].Produce)
	require.False(t, *rules[0].Produce)
	require.True(t, rules[1].ShouldProduce())
	require.Nil(t, rules[1].Produce)
}

func TestInitProxyTCPRuleRejectsInvalidTarget(t *testing.T) {
	_, err := Init(strings.NewReader(`rules:
  - match: tcp dst port 9889
    type: proxy_tcp
    target: tcp://127.0.0.1:9889
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many colons")
}

// TestFakePacket decodes the hand-built packet with gopacket to check every
// header field the filters can look at.
func TestFakePacket(t *testing.T) {
	for _, tc := range []struct {
		network  string
		src, dst string
	}{
		{"tcp", "1.1.1.1:12", "2.2.2.2:21"},
		{"udp", "1.1.1.1:5353", "2.2.2.2:53"},
		{"tcp", "[2001:db8::1]:40000", "[2001:db8::2]:22"},
		{"udp", "[2001:db8::1]:40000", "[2001:db8::2]:5060"},
	} {
		t.Run(tc.network+" "+tc.src, func(t *testing.T) {
			src, dst := netip.MustParseAddrPort(tc.src), netip.MustParseAddrPort(tc.dst)
			var buf [maxFakePacket]byte
			b, err := fakePacket(&buf, tc.network, src, dst)
			require.NoError(t, err)

			pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
			require.Nil(t, pkt.ErrorLayer(), "decode error")
			nl := pkt.NetworkLayer()
			require.NotNil(t, nl)
			require.Equal(t, src.Addr().String(), nl.NetworkFlow().Src().String())
			require.Equal(t, dst.Addr().String(), nl.NetworkFlow().Dst().String())

			switch tc.network {
			case "tcp":
				tcp, ok := pkt.TransportLayer().(*layers.TCP)
				require.True(t, ok, "no TCP layer")
				require.Equal(t, src.Port(), uint16(tcp.SrcPort))
				require.Equal(t, dst.Port(), uint16(tcp.DstPort))
				require.Equal(t, uint8(5), tcp.DataOffset)
			case "udp":
				udp, ok := pkt.TransportLayer().(*layers.UDP)
				require.True(t, ok, "no UDP layer")
				require.Equal(t, src.Port(), uint16(udp.SrcPort))
				require.Equal(t, dst.Port(), uint16(udp.DstPort))
				require.Equal(t, uint16(8), udp.Length)
			}
		})
	}
}

func TestFakePacketErrors(t *testing.T) {
	var buf [maxFakePacket]byte
	v4, v6 := netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("[2001:db8::1]:1")
	_, err := fakePacket(&buf, "sctp", v4, v4)
	require.ErrorContains(t, err, "unsupported network")
	_, err = fakePacket(&buf, "tcp", v4, v6)
	require.ErrorContains(t, err, "address family mismatch")
}

func TestMatchIPv6(t *testing.T) {
	rs := loadDefaultRules(t)
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 23}
	match, err := rs.Match("tcp", src, dst)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "telnet", match.Target)

	usrc := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000}
	udst := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060}
	match, err = rs.Match("udp", usrc, udst)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "sip", match.Target)
}

// TestMatchIPv4Mapped checks that an IPv4-mapped IPv6 address (as a dual-stack
// socket reports an IPv4 peer) is matched as IPv4.
func TestMatchIPv4Mapped(t *testing.T) {
	rs, err := Init(strings.NewReader("rules:\n  - match: ip and tcp dst port 23\n    type: conn_handler\n    target: telnet\n"))
	require.NoError(t, err)
	src := &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 40000}
	dst := &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 23}
	match, err := rs.Match("tcp", src, dst)
	require.NoError(t, err)
	require.NotNil(t, match)
}

func TestMatchRejectsNonIPAddr(t *testing.T) {
	rs := parseRules(t)
	_, err := rs.Match("tcp", &net.UnixAddr{Name: "/tmp/x", Net: "unix"}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
	require.Error(t, err)
}

func TestRunMatchTCP(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
	var (
		match *Rule
		err   error
	)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	match, err = rules.Match("tcp", srcAddr, dstAddr)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "test", match.Target)
}

func TestRunMatchUDP(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
	var (
		match *Rule
		err   error
	)

	srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	dstAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	match, err = rules.Match("udp", srcAddr, dstAddr)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "test", match.Target)
}

func TestRunMatchProxyTCP(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}

	match, err := rules.Match("tcp", srcAddr, dstAddr)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "proxy_tcp", match.Type)
	require.NotNil(t, match.ProxyTarget)
	require.Equal(t, "127.0.0.1:9889", match.ProxyTarget.DialAddress)
}

func TestBPF(t *testing.T) {
	buf := make([]byte, 65535)
	vm, err := compileMatcher("icmp")
	require.NoError(t, err)
	fh, err := os.Open("test.yaml")
	require.NoError(t, err)
	n, err := fh.Read(buf)
	require.NoError(t, err)
	rule := &Rule{matcher: vm}
	require.False(t, rule.matches(buf[:n]), "shouldn't match")
}

func TestWorkingMatch(t *testing.T) {
	packet := [...]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
		0x0, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
		0x08, 0x0, // ether type
		0x45, 0x0, 0x0, 0x3c, 0xa6, 0xc3, 0x40, 0x0, 0x40, 0x06, 0x3d, 0xd8, // ip header
		0xc0, 0xa8, 0x50, 0x2f, // src ip
		0xc0, 0xa8, 0x50, 0x2c, // dst ip
		0xaf, 0x14, // src port
		0x0, 0x50, // dst port
	}

	vm, err := compileMatcher("ip and tcp and port 80")
	require.NoError(t, err)
	rule := &Rule{matcher: vm}
	require.True(t, rule.matches(packet[:]), "didn't match")
}

func TestCompileMatcherRejectsInvalidFilter(t *testing.T) {
	_, err := compileMatcher("tcp dst port nope")
	require.Error(t, err)
}

func loadDefaultRules(t testing.TB) Rules {
	t.Helper()
	fh, err := os.Open("../config/rules.yaml")
	require.NoError(t, err)
	defer fh.Close()
	rs, err := Init(fh)
	require.NoError(t, err)
	return rs
}

// rulePorts returns every number that appears in a match expression of the
// default rules, plus a few unlisted ones: the ports where a filter can
// behave differently.
func rulePorts(rs Rules) []int {
	seen := map[int]bool{1: true, 80: true, 50000: true}
	for _, r := range rs {
		for _, f := range strings.FieldsFunc(r.Match, func(c rune) bool { return c < '0' || c > '9' }) {
			var p int
			for _, c := range f {
				p = p*10 + int(c-'0')
			}
			if p > 0 && p < 65536 {
				seen[p] = true
			}
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	return ports
}

func addr(network string, port int) net.Addr {
	ip := net.ParseIP("192.0.2.10")
	if network == "udp" {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// TestCompileMatcherAgreesWithLibpcap checks that the Go VM accepts exactly
// the packets libpcap's own filter accepts, for every default rule.
func TestCompileMatcherAgreesWithLibpcap(t *testing.T) {
	rs := loadDefaultRules(t)
	ports := rulePorts(rs)
	for _, r := range rs {
		ref, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, r.Match)
		require.NoError(t, err)
		for _, network := range []string{"tcp", "udp"} {
			for _, port := range ports {
				for _, sp := range [][2]uint16{{50000, uint16(port)}, {uint16(port), 50000}} {
					for _, ips := range [][2]string{{"192.0.2.1", "192.0.2.10"}, {"2001:db8::1", "2001:db8::2"}} {
						src := netip.AddrPortFrom(netip.MustParseAddr(ips[0]), sp[0])
						dst := netip.AddrPortFrom(netip.MustParseAddr(ips[1]), sp[1])
						var buf [maxFakePacket]byte
						b, err := fakePacket(&buf, network, src, dst)
						require.NoError(t, err)
						ci := gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b), Timestamp: time.Now()}
						require.Equal(t, ref.Matches(ci, b), r.matches(b), "%q %s %s->%s", r.Match, network, src, dst)
					}
				}
			}
		}
	}
}

// TestDefaultRulesMatchOnlyDestination guards against rules like
// "tcp dst port 23 or port 2323", where the bare "port 2323" matches any
// protocol and the source port too.
func TestDefaultRulesMatchOnlyDestination(t *testing.T) {
	rs := loadDefaultRules(t)
	for _, network := range []string{"tcp", "udp"} {
		for _, port := range rulePorts(rs) {
			// The source port must not change which rule a flow hits.
			want, err := rs.Match(network, addr(network, 50000), addr(network, 1))
			require.NoError(t, err)
			got, err := rs.Match(network, addr(network, port), addr(network, 1))
			require.NoError(t, err)
			require.Same(t, want, got, "%s from source port %d matched %q", network, port, got.Match)

			// A rule written for one protocol must not catch the other.
			match, err := rs.Match(network, addr(network, 50000), addr(network, port))
			require.NoError(t, err)
			if match != nil {
				other := "udp"
				if network == "udp" {
					other = "tcp"
				}
				require.False(t, strings.HasPrefix(match.Match, other), "%s dst port %d matched %q", network, port, match.Match)
			}
		}
	}
}

// TestMatchConcurrent runs TCP and UDP matching in parallel the way the two
// listeners do; run with -race.
func TestMatchConcurrent(t *testing.T) {
	rs := loadDefaultRules(t)
	done := make(chan struct{})
	for _, network := range []string{"tcp", "udp"} {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				if _, err := rs.Match(network, addr(network, 40000+i), addr(network, i)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	<-done
	<-done
}

func BenchmarkMatch(b *testing.B) {
	rs := loadDefaultRules(b)
	for _, tc := range []struct {
		name    string
		network string
		port    int
	}{
		{"tcp-first", "tcp", 23},
		{"tcp-catchall", "tcp", 1},
		{"udp-catchall", "udp", 9},
	} {
		src, dst := addr(tc.network, 40000), addr(tc.network, tc.port)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := rs.Match(tc.network, src, dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestRuleTLSMode(t *testing.T) {
	rs, err := Init(strings.NewReader(`rules:
  - match: tcp dst port 995
    type: conn_handler
    target: pop3
    tls: true
  - match: tcp dst port 110
    type: conn_handler
    target: pop3
  - match: tcp dst port 27017
    type: conn_handler
    target: mongodb
    tls: auto
  - match: tcp dst port 25
    type: conn_handler
    target: smtp
    tls: false
`))
	require.NoError(t, err)
	require.Equal(t, TLSOn, rs[0].TLS)
	require.Equal(t, TLSOff, rs[1].TLS)
	require.Equal(t, TLSAuto, rs[2].TLS)
	require.Equal(t, TLSOff, rs[3].TLS)

	_, err = Init(strings.NewReader("rules:\n  - match: tcp dst port 1\n    type: conn_handler\n    target: tcp\n    tls: maybe\n"))
	require.ErrorContains(t, err, "invalid tls mode")

	_, err = Init(strings.NewReader("rules:\n  - match: tcp dst port 443\n    type: proxy_tcp\n    target: 127.0.0.1:443\n    tls: true\n"))
	require.ErrorContains(t, err, "only supported on conn_handler")
}

func TestDefaultRulesRouteSMTPS(t *testing.T) {
	fh, err := os.Open("../config/rules.yaml")
	require.NoError(t, err)
	defer fh.Close()
	rs, err := Init(fh)
	require.NoError(t, err)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	for port, mode := range map[int]TLSMode{25: TLSOff, 465: TLSOn} {
		dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		match, err := rs.Match("tcp", srcAddr, dstAddr)
		require.NoError(t, err)
		require.NotNil(t, match, "port %d", port)
		require.Equal(t, "smtp", match.Target, "port %d", port)
		require.Equal(t, mode, match.TLS, "port %d", port)
	}
}

func TestDefaultRulesRouteDICOMPorts(t *testing.T) {
	fh, err := os.Open("../config/rules.yaml")
	require.NoError(t, err)
	defer fh.Close()
	rs, err := Init(fh)
	require.NoError(t, err)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	for _, port := range []int{104, 2345, 11112, 2761, 2762, 4242} {
		dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		match, err := rs.Match("tcp", srcAddr, dstAddr)
		require.NoError(t, err)
		require.NotNil(t, match, "port %d", port)
		require.Equal(t, "dicom", match.Target, "port %d", port)
		require.Equal(t, TLSAuto, match.TLS, "port %d", port)
	}
}

func TestDefaultRulesRouteSofiaPorts(t *testing.T) {
	fh, err := os.Open("../config/rules.yaml")
	require.NoError(t, err)
	defer fh.Close()
	rs, err := Init(fh)
	require.NoError(t, err)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	for _, port := range []int{34567, 34568} {
		dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		match, err := rs.Match("tcp", srcAddr, dstAddr)
		require.NoError(t, err)
		require.NotNil(t, match, "port %d", port)
		require.Equal(t, "sofia", match.Target, "port %d", port)
	}
}

func TestDefaultRulesRouteNetTcpPorts(t *testing.T) {
	fh, err := os.Open("../config/rules.yaml")
	require.NoError(t, err)
	defer fh.Close()
	rs, err := Init(fh)
	require.NoError(t, err)

	srcAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	for _, port := range []int{4025, 4026} {
		dstAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		match, err := rs.Match("tcp", srcAddr, dstAddr)
		require.NoError(t, err)
		require.NotNil(t, match, "port %d", port)
		require.Equal(t, "nettcp", match.Target, "port %d", port)
	}
}
