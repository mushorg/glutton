package rules

import (
	"net"
	"os"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func parseRules(t *testing.T) []*Rule {
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

func testConn(t *testing.T) net.Conn {
	ln, err := net.Listen("tcp4", "127.0.0.1:1234")
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer ln.Close()
	con, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, con)
	return con
}

func TestFakePacketBytes(t *testing.T) {
	conn := testConn(t)
	defer conn.Close()
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
}
