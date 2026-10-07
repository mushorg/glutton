package protocols

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/rules"
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
	require.Contains(t, m, "ike", "expected IKE handler")
	require.Contains(t, m, "sip", "expected SIP UDP handler")
	require.Contains(t, m, "openvpn", "expected OpenVPN UDP handler")
	require.Contains(t, m, "mdns", "expected mDNS UDP handler")
	require.Contains(t, m, "l2tp", "expected L2TP UDP handler")
	require.Contains(t, m, "raknet", "expected RakNet UDP handler")
	require.Contains(t, m, "kerberos", "expected Kerberos UDP handler")
	require.Contains(t, m, "coap", "expected CoAP UDP handler")
	require.Contains(t, m, "a2s", "expected A2S UDP handler")
	require.Contains(t, m, "ddp", "expected DDP UDP handler")
	require.Contains(t, m, "rtps", "expected RTPS UDP handler")
	require.Contains(t, m, "proxy_udp", "expected proxy_udp handler")
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
	require.Contains(t, m, "mcp", "expected MCP handler")
	require.Contains(t, m, "memcache", "expected memcache handler")
	require.Contains(t, m, "opcua", "expected OPC UA handler")
	require.Contains(t, m, "mctp", "expected MCTP handler")
	require.Contains(t, m, "dicom", "expected DICOM handler")
	require.Contains(t, m, "rfb", "expected RFB handler")
	require.Contains(t, m, "pop3", "expected POP3 handler")
	require.Contains(t, m, "whois", "expected WHOIS handler")
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

func TestServeTLS(t *testing.T) {
	rule := &rules.Rule{Target: "pop3", TLS: true}
	newHP := func(produced *[]string) *mocks.MockHoneypot {
		h := &mocks.MockHoneypot{}
		h.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
		h.EXPECT().ProduceTCP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(handler string, _ net.Conn, md connection.Metadata, payload []byte, _ interface{}) error {
				*produced = append(*produced, handler)
				return nil
			})
		return h
	}
	log := &mocks.MockLogger{}
	log.EXPECT().Debug(mock.Anything, mock.Anything, mock.Anything).Maybe()
	log.EXPECT().Debug(mock.Anything, mock.Anything).Maybe()

	t.Run("handshake ok runs handler on plaintext", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
		var produced []string
		var gotTLS *connection.TLSInfo
		var gotRead string
		fn := func(_ context.Context, c net.Conn, md connection.Metadata, _ interfaces.Logger, _ interfaces.Honeypot) error {
			gotTLS = md.TLS
			buf := make([]byte, 5)
			_, err := io.ReadFull(c, buf)
			gotRead = string(buf)
			_ = c.Close()
			return err
		}
		done := make(chan error, 1)
		go func() {
			done <- serveTLS(context.Background(), fn, server, connection.Metadata{Rule: rule}, log, newHP(&produced))
		}()
		tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
		require.NoError(t, tc.Handshake())
		_, err := tc.Write([]byte("hello"))
		require.NoError(t, err)
		require.NoError(t, <-done)
		require.Equal(t, "hello", gotRead)
		require.Equal(t, "mail.example.com", gotTLS.ServerName)
		require.Empty(t, produced, "wrapper must not produce when the handler ran")
	})

	t.Run("failed handshake produces one event and skips handler", func(t *testing.T) {
		client, server := net.Pipe()
		var produced []string
		called := false
		fn := func(context.Context, net.Conn, connection.Metadata, interfaces.Logger, interfaces.Honeypot) error {
			called = true
			return nil
		}
		require.NoError(t, client.Close())
		require.NoError(t, serveTLS(context.Background(), fn, server, connection.Metadata{Rule: rule}, log, newHP(&produced)))
		require.False(t, called)
		require.Equal(t, []string{"pop3"}, produced)
	})
}
