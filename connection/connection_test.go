package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/mushorg/glutton/rules"
	"github.com/stretchr/testify/require"
)

var localhost1234Key = CKey([2]uint64{9580489724559085892, 13327978790310486453})

func testTCPConn(t *testing.T) (net.Conn, CKey) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	require.NotNil(t, ln)
	t.Cleanup(func() {
		_ = ln.Close()
	})

	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	require.NoError(t, err)
	key, err := NewConnKeyByString(host, port)
	require.NoError(t, err)

	return conn, key
}

func TestNewConnKeyByString(t *testing.T) {
	ck, err := NewConnKeyByString("127.0.0.1", "1234")
	require.NoError(t, err)
	require.Equal(t, localhost1234Key, ck)
}

func TestNewConnKeyFromNetConn(t *testing.T) {
	conn, expected := testTCPConn(t)
	ck, err := NewConnKeyFromNetConn(conn)
	require.NoError(t, err)
	require.Equal(t, expected, ck)
}

func TestNewConnTable(t *testing.T) {
	table := New(context.Background())
	require.NotNil(t, table)
}

func TestRegister(t *testing.T) {
	table := New(context.Background())
	targetPort := 4321
	m1, err := table.Register("127.0.0.1", "1234", uint16(targetPort), "192.0.2.1", &rules.Rule{})
	require.NoError(t, err)
	require.NotNil(t, m1)
	m2 := table.Get(localhost1234Key)
	require.NotNil(t, m1)
	require.Equal(t, targetPort, int(m2.TargetPort))
	require.Equal(t, "192.0.2.1", m2.TargetIP)
	require.Equal(t, m1, m2)
}

func TestRegisterConn(t *testing.T) {
	conn, ck := testTCPConn(t)
	table := New(context.Background())
	md, err := table.RegisterConn(conn, &rules.Rule{Target: "tcp"})
	require.NoError(t, err)
	require.NotNil(t, md)
	m := table.Get(ck)
	require.NotNil(t, m)
	require.Equal(t, "tcp", m.Rule.Target)
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, host, md.TargetIP)
}

func TestFlushOlderThan(t *testing.T) {
	table := New(context.Background())
	targetPort := 4321
	md, err := table.Register("127.0.0.1", "1234", uint16(targetPort), "", &rules.Rule{})
	require.NoError(t, err)
	require.NotNil(t, md)
	table.FlushOlderThan(time.Duration(0))
	m := table.Get(localhost1234Key)
	require.Empty(t, m)
}

func TestEndReasonFromRead(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, EndClientClose},
		{io.EOF, EndClientClose},
		{net.ErrClosed, EndClientClose},
		{os.ErrDeadlineExceeded, EndTimeout},
		{context.DeadlineExceeded, EndTimeout},
		{fmt.Errorf("read: %w", syscall.ECONNRESET), EndClientReset},
		{io.ErrUnexpectedEOF, EndReadError},
		{errors.New("invalid length"), EndReadError},
	} {
		require.Equal(t, tc.want, EndReasonFromRead(tc.err), "%v", tc.err)
	}
}

func TestEndReasonFromReadTCPReset(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	server, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	// linger 0 makes Close send RST instead of FIN
	require.NoError(t, client.(*net.TCPConn).SetLinger(0))
	require.NoError(t, client.Close())

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = server.Read(make([]byte, 1))
	require.Error(t, err)
	require.Equal(t, EndClientReset, EndReasonFromRead(err))
}
