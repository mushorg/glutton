package glutton

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestPort2Protocol(t *testing.T) {
}

func TestNewGlutton(t *testing.T) {
	viper.Set("var-dir", "/tmp/glutton")
	viper.Set("confpath", "./config")
	g, err := New()
	require.NoError(t, err, "error initializing glutton")
	require.NotNil(t, g, "nil instance but no error")
	g.registerHandlers()
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
