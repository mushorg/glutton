package protocols

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// read frame 1 of ochi event f30046fd-0bb9-4f7c-b9c3-e25df4ddcff5 (tcp/10554)
var rtspOchiOptions = []byte("OPTIONS rtsp://1.2.3.4:10554 RTSP/1.0\r\nCSeq: 1\r\n\r\n")

// sendRTSP writes req and checks the reply status line and CSeq echo.
func sendRTSP(t *testing.T, req []byte, status, cseq string) func(net.Conn) {
	return func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "RTSP/1.0 "+status+"\r\n", line)
		line, err = r.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "CSeq: "+cseq+"\r\n", line)
	}
}

func TestRTSPTargetRoutesRTSP(t *testing.T) {
	names := dispatchTarget(t, "rtsp", 10554, sendRTSP(t, rtspOchiOptions, "200 OK", "1"))
	require.Equal(t, []string{"rtsp"}, names)
}

func TestRTSPTargetFallsBackToCatchAll(t *testing.T) {
	// HTTP on an RTSP port reaches the HTTP handler through the catch-all;
	// HTTP produces its session event later, so the reply proves the route
	names := dispatchTarget(t, "rtsp", 554, func(c net.Conn) {
		_, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(line, "HTTP/1.1 "), line)
	})
	require.Empty(t, names)

	names = dispatchTarget(t, "rtsp", 554, func(c net.Conn) {
		_, err := c.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096)) // one random-bytes reply
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestCatchAllRoutesRTSPBeforeHTTP(t *testing.T) {
	start := time.Now()
	names := dispatchTarget(t, "tcp", 7000, sendRTSP(t, rtspOchiOptions, "200 OK", "1"))
	require.Equal(t, []string{"rtsp"}, names)
	// the line peek ends at the newline, not at the peek deadline
	require.Less(t, time.Since(start), 150*time.Millisecond)

	describe := []byte("DESCRIBE rtsp://1.2.3.4:7000/live RTSP/1.0\r\nCSeq: 2\r\n\r\n")
	names = dispatchTarget(t, "tcp", 7000, sendRTSP(t, describe, "401 Unauthorized", "2"))
	require.Equal(t, []string{"rtsp"}, names)
}

func TestCatchAllHTTPOptionsStillHTTP(t *testing.T) {
	// HTTP produces its session event after an idle delay: the HTTP reply
	// and the absence of an rtsp/tcp event prove the route
	names := dispatchTarget(t, "tcp", 7000, func(c net.Conn) {
		_, err := c.Write([]byte("OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(line, "HTTP/1.1 "), line)
	})
	require.Empty(t, names)
}
