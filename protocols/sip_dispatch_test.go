package protocols

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// read frame 1 of ochi event 47dbaf4a-0414-4a41-902e-60437cc7142d (tcp/65060)
var sipOchiRegister = []byte("REGISTER sip:1.2.3.4 SIP/2.0\r\n" +
	"Via: SIP/2.0/TCP 209.222.101.54:56911;branch=z9hG4bK820645100\r\n" +
	"Max-Forwards: 70\r\n" +
	"From: <sip:211@1.2.3.4>;tag=1932083941\r\n" +
	"To: <sip:211@1.2.3.4>\r\n" +
	"Call-ID: 514660692-570740914-539962798\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"Contact: <sip:211@209.222.101.54:56910>\r\n" +
	"Content-Length: 0\r\n" +
	"User-Agent: AsTa\r\n\r\n")

// sendExpecting writes req and checks the first reply line starts with prefix.
func sendExpecting(t *testing.T, req []byte, prefix string) func(net.Conn) {
	return func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(line, prefix), line)
	}
}

func TestCatchAllRoutesSIP(t *testing.T) {
	names := dispatchTarget(t, "tcp", 65060, sendExpecting(t, sipOchiRegister, "SIP/2.0 "))
	require.Equal(t, []string{"sip"}, names)
}

func TestCatchAllSIPOptionsIsNotHTTP(t *testing.T) {
	req := []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 198.51.100.7:5060;branch=z9hG4bK1\r\n" +
		"From: <sip:100@1.2.3.4>;tag=1\r\nTo: <sip:100@1.2.3.4>\r\nCall-ID: a1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
	names := dispatchTarget(t, "tcp", 7002, sendExpecting(t, req, "SIP/2.0 "))
	require.Equal(t, []string{"sip"}, names)
}

func TestCatchAllHTTPOptionsStaysHTTP(t *testing.T) {
	// HTTP produces its session event later, so the reply proves the route
	names := dispatchTarget(t, "tcp", 7003, sendExpecting(t, []byte("OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n"), "HTTP/"))
	require.Empty(t, names)
}
