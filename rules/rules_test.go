package rules

import (
	"net"
	"os"
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
	rules, err := ParseRuleSpec(fh)
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
	for i := range rules {
		err := InitRule(i, rules[i])
		require.NoError(t, err)
	}

	for _, rule := range rules {
		require.True(t, rule.isInit)
		require.NotNil(t, rule.matcher)
	}
}

func TestSplitAddr(t *testing.T) {
	ip, port, err := splitAddr("192.168.1.1:8080")
	require.NoError(t, err)
	require.True(t, net.ParseIP("192.168.1.1").Equal(ip))
	require.Equal(t, layers.TCPPort(8080), port)
}

func testConn(t *testing.T) (net.Conn, net.Listener) {
	ln, err := net.Listen("tcp4", "127.0.0.1:1234")
	require.NoError(t, err)
	require.NotNil(t, ln)
	con, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, con)
	return con, ln
}

func TestFakePacketBytes(t *testing.T) {
	conn, ln := testConn(t)
	defer func() {
		conn.Close()
		ln.Close()
	}()
	_, err := fakePacketBytes(conn)
	require.NoError(t, err)
}

func TestRunMatch(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
	for i := range rules {
		err := InitRule(i, rules[i])
		require.NoError(t, err)
	}
	conn, ln := testConn(t)
	defer func() {
		conn.Close()
		ln.Close()
	}()
	println(conn.RemoteAddr().String())
	var (
		match *Rule
		err   error
	)

	match, err = rules.Match(conn)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "test", match.Target)
}

func TestBPF(t *testing.T) {
	buf := make([]byte, 65535)
	bpfi, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, "icmp")
	require.NoError(t, err)
	fh, err := os.Open("test.yaml")
	require.NoError(t, err)
	n, err := fh.Read(buf)
	require.NoError(t, err)
	ci := gopacket.CaptureInfo{CaptureLength: n, Length: n, Timestamp: time.Now()}
	if bpfi.Matches(ci, buf) {
		t.Error("foo")
	}
}
