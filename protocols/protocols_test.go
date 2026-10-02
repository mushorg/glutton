package protocols

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testConn(t *testing.T) (net.Conn, func() error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NotNil(t, l)
	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
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
	err := m["udp"](ctx, &net.UDPAddr{}, &net.UDPAddr{}, []byte{}, connection.Metadata{})
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

func TestParseTCPProtocol(t *testing.T) {
	logger := &mocks.MockLogger{}
	logger.EXPECT().Info(mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything).Return().Maybe()

	if err := spicy.Initialize(logger); err != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", err)
	}

	tests := []struct {
		name     string
		sample   []byte
		protocol string
		ok       bool
	}{
		{
			name:     "http",
			sample:   []byte("GET "),
			protocol: "http",
			ok:       true,
		},
		{
			name:     "rdp",
			sample:   []byte{0x03, 0x00, 0x00, 0x2b},
			protocol: "rdp",
			ok:       true,
		},
		{
			name: "mongodb",
			sample: []byte{
				0x10, 0x00, 0x00, 0x00,
				0x01, 0x02, 0x03, 0x04,
				0x00, 0x00, 0x00, 0x00,
				0xdd, 0x07, 0x00, 0x00,
			},
			protocol: "mongodb",
			ok:       true,
		},
		{
			name:   "invalid",
			sample: []byte{0xff, 0x00, 0x01, 0x02},
			ok:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol, ok := parseTCPProtocol(test.sample, logger)
			require.Equal(t, test.ok, ok)
			require.Equal(t, test.protocol, protocol)
		})
	}
}
