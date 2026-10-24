package protocols

import (
	"bufio"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPPTargetRoutesHTTP(t *testing.T) {
	// synthetic Get-Printer-Attributes with only the required operation attributes
	body := "\x02\x00\x00\x0b\x00\x00\x00\x01\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02en\x03"
	names := dispatchTarget(t, "ipp", 631, func(c net.Conn) {
		_, err := c.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "HTTP/1.1 200 OK\r\n", line)
	})
	require.Equal(t, []string{"ipp"}, names)
}

func TestIPPTargetFallsBackToCatchAll(t *testing.T) {
	names := dispatchTarget(t, "ipp", 631, func(c net.Conn) {
		_, err := c.Write([]byte("*1\r\n$4\r\nPING\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "+PONG\r\n", line)
	})
	require.Equal(t, []string{"redis"}, names)

	names = dispatchTarget(t, "ipp", 631, func(c net.Conn) {
		_, err := c.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096)) // one random-bytes reply
	})
	require.Equal(t, []string{"tcp"}, names)
}
