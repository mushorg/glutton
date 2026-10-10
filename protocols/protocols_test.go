package protocols

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
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
	require.Contains(t, m, "knx", "expected KNX UDP handler")
	require.Contains(t, m, "dtls", "expected DTLS UDP handler")
	require.Contains(t, m, "wsdiscovery", "expected WS-Discovery UDP handler")
	require.Contains(t, m, "hiflying", "expected Hi-Flying UDP handler")
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
	require.Contains(t, m, "adb", "expected ADB handler")
	require.Contains(t, m, "minecraft", "expected Minecraft handler")
	require.Contains(t, m, "socks", "expected SOCKS handler")
	require.Contains(t, m, "dnp3", "expected DNP3 handler")
	require.Contains(t, m, "enip", "expected EtherNet/IP handler")
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

// tlsTestHoneypot records the handler names of events the TLS wrapper produces.
func tlsTestHoneypot(produced *[]string) *mocks.MockHoneypot {
	h := &mocks.MockHoneypot{}
	h.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	h.EXPECT().ProduceTCP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(handler string, _ net.Conn, _ connection.Metadata, _ []byte, _ interface{}) error {
			*produced = append(*produced, handler)
			return nil
		}).Maybe()
	return h
}

func tlsTestLogger() *mocks.MockLogger {
	log := &mocks.MockLogger{}
	log.EXPECT().Debug(mock.Anything, mock.Anything, mock.Anything).Maybe()
	log.EXPECT().Debug(mock.Anything, mock.Anything).Maybe()
	return log
}

// recordingHandler reads n bytes from the connection it is given and records
// them along with the TLS metadata.
type recordingHandler struct {
	n      int
	called bool
	tls    *connection.TLSInfo
	read   string
}

func (r *recordingHandler) handle(_ context.Context, c net.Conn, md connection.Metadata) error {
	r.called = true
	r.tls = md.TLS
	if r.n > 0 {
		buf := make([]byte, r.n)
		_, err := io.ReadFull(c, buf)
		r.read = string(buf)
		if err != nil {
			return err
		}
	}
	return c.Close()
}

func runWithTLS(t *testing.T, mode rules.TLSMode, rh *recordingHandler, produced *[]string, client func(net.Conn)) {
	t.Helper()
	clientConn, server := net.Pipe()
	defer clientConn.Close()
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	md := connection.Metadata{Rule: &rules.Rule{Target: "pop3", TLS: mode}}
	done := make(chan error, 1)
	go func() {
		done <- withTLS(rh.handle, tlsTestLogger(), tlsTestHoneypot(produced))(context.Background(), server, md)
	}()
	client(clientConn)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
}

func tlsClientSend(t *testing.T, msg string) func(net.Conn) {
	return func(c net.Conn) {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.com"})
		require.NoError(t, tc.Handshake())
		_, err := tc.Write([]byte(msg))
		require.NoError(t, err)
		// net.Pipe is unbuffered: drain so the server's close_notify does not block
		go func() { _, _ = io.Copy(io.Discard, tc) }()
	}
}

func TestWithTLS(t *testing.T) {
	for _, mode := range []rules.TLSMode{rules.TLSOn, rules.TLSAuto} {
		t.Run(fmt.Sprintf("mode %d: TLS client gets plaintext handler", mode), func(t *testing.T) {
			var produced []string
			rh := &recordingHandler{n: 5}
			runWithTLS(t, mode, rh, &produced, tlsClientSend(t, "hello"))
			require.Equal(t, "hello", rh.read)
			require.Equal(t, "mail.example.com", rh.tls.ServerName)
			require.NotEmpty(t, rh.tls.Version)
			require.Len(t, rh.tls.JA3, 32)
			require.Regexp(t, `^t13d\d{4}00_[0-9a-f]{12}_[0-9a-f]{12}$`, rh.tls.JA4)
			require.Empty(t, produced, "wrapper must not produce when the handler ran")
		})
	}

	t.Run("on: closed client produces one event, handler skipped", func(t *testing.T) {
		var produced []string
		rh := &recordingHandler{}
		runWithTLS(t, rules.TLSOn, rh, &produced, func(c net.Conn) { _ = c.Close() })
		require.False(t, rh.called)
		require.Equal(t, []string{"pop3"}, produced)
	})

	t.Run("auto: plaintext client-first goes to handler with bytes intact", func(t *testing.T) {
		var produced []string
		rh := &recordingHandler{n: 10}
		runWithTLS(t, rules.TLSAuto, rh, &produced, func(c net.Conn) {
			_, err := c.Write([]byte("USER bob\r\n"))
			require.NoError(t, err)
		})
		require.Equal(t, "USER bob\r\n", rh.read)
		require.Nil(t, rh.tls)
		require.Empty(t, produced)
	})

	t.Run("auto: silent client gets the plaintext handler after the wait", func(t *testing.T) {
		var produced []string
		rh := &recordingHandler{}
		start := time.Now()
		runWithTLS(t, rules.TLSAuto, rh, &produced, func(net.Conn) {})
		require.True(t, rh.called)
		require.Nil(t, rh.tls)
		require.GreaterOrEqual(t, time.Since(start), tlsAutoWait)
		require.Empty(t, produced)
	})

	t.Run("auto: 0x16 without a TLS version is plaintext", func(t *testing.T) {
		var produced []string
		rh := &recordingHandler{n: 4}
		// a MongoDB message of length 22 starts 16 00 00 00
		runWithTLS(t, rules.TLSAuto, rh, &produced, func(c net.Conn) {
			_, err := c.Write([]byte{0x16, 0x00, 0x00, 0x00})
			require.NoError(t, err)
		})
		require.True(t, rh.called)
		require.Nil(t, rh.tls)
		require.Equal(t, string([]byte{0x16, 0x00, 0x00, 0x00}), rh.read)
	})

	t.Run("off: handler gets the raw connection", func(t *testing.T) {
		var produced []string
		rh := &recordingHandler{n: 3}
		runWithTLS(t, rules.TLSOff, rh, &produced, func(c net.Conn) {
			_, err := c.Write([]byte("abc"))
			require.NoError(t, err)
		})
		require.Equal(t, "abc", rh.read)
		require.Nil(t, rh.tls)
	})
}

func TestLooksLikeTLSRecord(t *testing.T) {
	require.True(t, looksLikeTLSRecord([]byte{0x16, 0x03, 0x01}))
	require.True(t, looksLikeTLSRecord([]byte{0x16, 0x03, 0x03}))
	require.False(t, looksLikeTLSRecord([]byte{0x16, 0x03, 0x05}))
	require.False(t, looksLikeTLSRecord([]byte{0x16, 0x00, 0x00}))
	require.False(t, looksLikeTLSRecord([]byte("GET")))
	require.False(t, looksLikeTLSRecord([]byte{0x16}))
}
