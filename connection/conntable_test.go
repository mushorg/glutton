package connection

import (
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/rules"
	"github.com/stretchr/testify/require"
)

var testck = CKey([2]uint64{9580489724559085892, 13327978790310486453})

func TestNewConnKeyByString(t *testing.T) {
	ck, err := NewConnKeyByString("127.0.0.1", "1234")
	require.NoError(t, err)
	require.Equal(t, testck, ck)
}

func TestNewConnKeyFromNetConn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:1234")
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer ln.Close()
	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
	ck, err := NewConnKeyFromNetConn(conn)
	require.NoError(t, err)
	require.Equal(t, testck, ck)
}

func TestNewConnTable(t *testing.T) {
	table := New()
	require.NotNil(t, table)
}

func TestRegister(t *testing.T) {
	table := New()
	targetPort := 4321
	err := table.Register("127.0.0.1", "1234", uint16(targetPort), &rules.Rule{})
	require.NoError(t, err)
	m := table.Get(testck)
	require.NotNil(t, m)
	require.Equal(t, targetPort, int(m.TargetPort))
}

func TestRegisterConn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:1234")
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer ln.Close()
	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
	table := New()
	err = table.RegisterConn(conn, &rules.Rule{Target: "default"})
	require.NoError(t, err)
	m := table.Get(testck)
	require.NotNil(t, m)
	require.Equal(t, "default", m.Rule.Target)
}

func TestFlushOlderThan(t *testing.T) {
	table := New()
	targetPort := 4321
	err := table.Register("127.0.0.1", "1234", uint16(targetPort), &rules.Rule{})
	require.NoError(t, err)
	table.FlushOlderThan(time.Duration(0))
	m := table.Get(testck)
	require.Nil(t, m)
}
