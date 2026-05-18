package protocols

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testConn(t *testing.T) (net.Conn, func() error) {
	l, err := net.Listen("tcp", ":1235")
	require.NoError(t, err)
	require.NotNil(t, l)
	conn, err := net.Dial("tcp", ":1235")
	require.NoError(t, err)
	err = conn.SetDeadline(time.Now().Add(time.Millisecond))
	require.NoError(t, err)
	return conn, l.Close
}

func TestMapUDPProtocolHandlers(t *testing.T) {
	h := &mocks.MockHoneypot{}
	h.EXPECT().ProduceUDP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	l := &mocks.MockLogger{}
	l.EXPECT().Info(mock.Anything).Return().Maybe()

	m := MapUDPProtocolHandlers(l, h)
	require.NotEmpty(t, m, "should get a non-empty map")
	h.AssertExpectations(t)
	l.AssertExpectations(t)
	require.Contains(t, m, "udp", "expected UDP handler")
	ctx := context.Background()
	_, err := m["udp"](ctx, &net.UDPAddr{}, &net.UDPAddr{}, []byte{}, connection.Metadata{})
	require.NoError(t, err, "expected no error from connection handler")
}

func TestMapTCPProtocolHandlers(t *testing.T) {
	h := &mocks.MockHoneypot{}
	l := &mocks.MockLogger{}
	l.EXPECT().Debug(mock.Anything, mock.Anything).Return().Maybe()

	m := MapTCPProtocolHandlers(l, h)
	require.NotEmpty(t, m, "should get a non-empty map")
	h.AssertExpectations(t)
	l.AssertExpectations(t)
	require.Contains(t, m, "tcp", "expected TCP handler")
	ctx := context.Background()
	conn, close := testConn(t)
	defer close()
	err := m["tcp"](ctx, conn, connection.Metadata{})
	require.NoError(t, err, "expected no error from connection handler")
}
