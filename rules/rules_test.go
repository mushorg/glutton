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

func TestSplitAddr(t *testing.T) {
	ip, port, err := splitAddr("192.168.1.1:8080")
	require.NoError(t, err)
	require.Equal(t, "192.168.1.1", ip)
	require.Equal(t, uint16(8080), port)
}

func testConn(t *testing.T) (net.Conn, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:1234")
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
	b, err := fakePacketBytes("tcp", "1.1.1.1", "2.2.2.2", 12, 21)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

func TestRunMatchTCP(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
	conn, ln := testConn(t)
	defer func() {
		conn.Close()
		ln.Close()
	}()
	var (
		match *Rule
		err   error
	)

	match, err = rules.Match("tcp", conn.LocalAddr(), conn.RemoteAddr())
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, "test", match.Target)
}

func TestRunMatchUDP(t *testing.T) {
	rules := parseRules(t)
	require.NotEmpty(t, rules)
	conn, ln := testConn(t)
	defer func() {
		conn.Close()
		ln.Close()
	}()
	var (
		match *Rule
		err   error
	)

	match, err = rules.Match("udp", conn.LocalAddr(), conn.RemoteAddr())
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
		t.Error("shouldn't match")
	}
}

func TestWorkingMatch(t *testing.T) {
	snaplen := 65535
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

	bpfi, _ := pcap.NewBPF(layers.LinkTypeEthernet, snaplen, "ip and tcp and port 80")
	ci := gopacket.CaptureInfo{
		InterfaceIndex: 0,
		CaptureLength:  len(packet),
		Length:         len(packet),
		Timestamp:      time.Now(),
	}
	if !bpfi.Matches(ci, packet[:]) {
		t.Fatal("didn't match")
	}
}
