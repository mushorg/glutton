package connection

import (
	"net"
	"testing"
	"time"

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
	con, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, con)
	defer con.Close()
	ck, err := NewConnKeyFromNetConn(con)
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
	err := table.Register("127.0.0.1", "1234", uint16(targetPort))
	require.NoError(t, err)
	m := table.Get(testck)
	require.NotNil(t, m)
	require.Equal(t, targetPort, int(m.TargetPort))
}

func TestFlushOlderThan(t *testing.T) {
	table := New()
	targetPort := 4321
	err := table.Register("127.0.0.1", "1234", uint16(targetPort))
	require.NoError(t, err)
	table.FlushOlderThan(time.Duration(0))
	m := table.Get(testck)
	require.Nil(t, m)
}
