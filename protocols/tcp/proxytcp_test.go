package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type recordingLogger struct {
	mtx    sync.Mutex
	infos  []string
	debugs []string
	errs   []string
	warns  []string
	fields []any
}

func (l *recordingLogger) Info(msg string, fields ...any) {
	l.record(&l.infos, msg, fields...)
}

func (l *recordingLogger) Debug(msg string, fields ...any) {
	l.record(&l.debugs, msg, fields...)
}

func (l *recordingLogger) Error(msg string, fields ...any) {
	l.record(&l.errs, msg, fields...)
}

func (l *recordingLogger) Warn(msg string, fields ...any) {
	l.record(&l.warns, msg, fields...)
}

func (l *recordingLogger) record(target *[]string, msg string, fields ...any) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	*target = append(*target, msg)
	l.fields = append(l.fields, fields...)
}

func (l *recordingLogger) hasAttr(key, value string) bool {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	for _, field := range l.fields {
		attr, ok := field.(slog.Attr)
		if !ok {
			continue
		}
		if attr.Key == key && attr.Value.String() == value {
			return true
		}
	}
	return false
}

type producedTCP struct {
	protocol string
	decoded  interface{}
}

type fakeHoneypot struct {
	produced chan producedTCP
}

func newFakeHoneypot() *fakeHoneypot {
	return &fakeHoneypot{produced: make(chan producedTCP, 4)}
}

func (h *fakeHoneypot) ProduceTCP(protocol string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	h.produced <- producedTCP{protocol: protocol, decoded: decoded}
	return nil
}

func (h *fakeHoneypot) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	return nil
}

func (h *fakeHoneypot) ConnectionByFlow([2]uint64) connection.Metadata {
	return connection.Metadata{}
}

func (h *fakeHoneypot) UpdateConnectionTimeout(context.Context, net.Conn) error {
	return nil
}

func (h *fakeHoneypot) MetadataByConnection(net.Conn) (connection.Metadata, error) {
	return connection.Metadata{}, nil
}

func setCapture(t *testing.T, enabled bool) {
	t.Helper()

	previousCapture := viper.Get("capture_traffic.enabled")
	previousMaxPayload := viper.Get("max_tcp_payload")
	previousTimeout := viper.Get("conn_timeout")
	viper.Set("capture_traffic.enabled", enabled)
	viper.Set("max_tcp_payload", 4096)
	viper.Set("conn_timeout", 0)
	t.Cleanup(func() {
		viper.Set("capture_traffic.enabled", previousCapture)
		viper.Set("max_tcp_payload", previousMaxPayload)
		viper.Set("conn_timeout", previousTimeout)
	})
}

func proxyMetadata(target string) connection.Metadata {
	return connection.Metadata{
		Rule: &rules.Rule{
			Type: "proxy_tcp",
			ProxyTarget: &rules.ProxyTarget{
				Host:        "127.0.0.1",
				Port:        0,
				DialAddress: target,
			},
		},
	}
}

func startTCPServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	done := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("server at %s did not finish", listener.Addr().String())
		}
	})

	go func() {
		defer close(done)

		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handle(conn)
	}()

	return listener.Addr().String()
}

func startProxyServer(t *testing.T, target string, hp *fakeHoneypot, logger *recordingLogger) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatalf("proxy at %s did not finish", listener.Addr().String())
		}
	})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- HandleProxyTCP(context.Background(), conn, proxyMetadata(target), logger, hp)
	}()

	return listener.Addr().String()
}

func waitProduced(t *testing.T, hp *fakeHoneypot) producedTCP {
	t.Helper()

	select {
	case event := <-hp.produced:
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced TCP event")
	}
	return producedTCP{}
}

func TestHandleProxyAfterCloseWrite(t *testing.T) {
	setCapture(t, false)

	targetAddr := startTCPServer(t, func(conn net.Conn) {
		request, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, "request", string(request))

		_, err = conn.Write([]byte("response"))
		require.NoError(t, err)
	})

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	proxyAddr := startProxyServer(t, targetAddr, hp, logger)

	client, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	response, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Equal(t, "response", string(response))

	event := waitProduced(t, hp)
	require.Equal(t, "proxy_tcp", event.protocol)
	require.Empty(t, event.decoded)
	require.True(t, logger.hasAttr("handler", "proxy_tcp"))
}

func TestHandleProxyTCP(t *testing.T) {
	setCapture(t, true)

	targetAddr := startTCPServer(t, func(conn net.Conn) {
		request, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, "client-payload", string(request))

		_, err = conn.Write([]byte("target-response"))
		require.NoError(t, err)
	})

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	proxyAddr := startProxyServer(t, targetAddr, hp, logger)

	client, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Write([]byte("client-payload"))
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	response, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Equal(t, "target-response", string(response))

	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]event)
	require.True(t, ok)
	require.Len(t, events, 2)

	payloads := map[string]bool{}
	for _, captured := range events {
		payloads[string(captured.Payload)] = true
		require.NotEmpty(t, captured.Direction)
		require.NotEmpty(t, captured.PayloadHash)
	}
	require.True(t, payloads["client-payload"])
	require.True(t, payloads["target-response"])
}

func TestWriter(t *testing.T) {
	writeErr := errors.New("short write")
	logger := &recordingLogger{}
	session := &session{producer: true, payloadSize: 4096}
	writer := &writer{
		conn:    partialWriteConn{written: 3, err: writeErr},
		session: session,
		logger:  logger,
		dir:     "client->target",
		name:    "client->target dst",
	}

	n, err := writer.Write([]byte("abcdef"))
	require.ErrorIs(t, err, writeErr)
	require.Equal(t, 3, n)

	event := writer.event()
	require.NotNil(t, event)
	require.Equal(t, "abc", string(event.Payload))
	require.Equal(t, int64(3), event.Bytes)
	require.False(t, event.Truncated)
	require.Equal(t, int64(3), writer.written)
}

// test capture writer skipped failed writer
func TestFailedWrites(t *testing.T) {
	writeErr := errors.New("write failed")
	logger := &recordingLogger{}
	session := &session{producer: true, payloadSize: 4096}
	writer := &writer{
		conn:    partialWriteConn{written: 0, err: writeErr},
		session: session,
		logger:  logger,
		dir:     "client->target",
		name:    "client->target dst",
	}

	n, err := writer.Write([]byte("abcdef"))
	require.ErrorIs(t, err, writeErr)
	require.Zero(t, n)
	require.Nil(t, writer.event())
	require.Zero(t, writer.written)
}

// test capture writer returns short write error
func TestShortWriteError(t *testing.T) {
	logger := &recordingLogger{}
	session := &session{producer: true, payloadSize: 4096}
	writer := &writer{
		conn:    partialWriteConn{written: 3},
		session: session,
		logger:  logger,
		dir:     "client->target",
		name:    "client->target dst",
	}

	n, err := writer.Write([]byte("abcdef"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Equal(t, 3, n)
	event := writer.event()
	require.Equal(t, "abc", string(event.Payload))
	require.Equal(t, int64(3), event.Bytes)
	require.False(t, event.Truncated)
}

// test capture writer caps captured bytes
func TestWriterByteCaps(t *testing.T) {
	logger := &recordingLogger{}
	session := &session{producer: true, payloadSize: 4}
	writer := &writer{
		conn:    partialWriteConn{written: 6},
		session: session,
		logger:  logger,
		dir:     "client->target",
		name:    "client->target dst",
	}

	n, err := writer.Write([]byte("abcdef"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	event := writer.event()
	require.Equal(t, "abcd", string(event.Payload))
	require.Equal(t, int64(6), event.Bytes)
	require.True(t, event.Truncated)
}

func TestExpectedPipeErrorAllowsNotConnected(t *testing.T) {
	err := fmt.Errorf("close read: %w", syscall.ENOTCONN)

	require.True(t, expectedPipeError(err))
}

// test proxy handler closes connection on missing metadata
func TestMissingMetadata(t *testing.T) {
	setCapture(t, true)

	client, server := net.Pipe()
	defer client.Close()

	logger := &recordingLogger{}
	err := HandleProxyTCP(context.Background(), server, connection.Metadata{}, logger, newFakeHoneypot())
	require.NoError(t, err)
	require.True(t, logger.hasAttr("handler", "proxy_tcp"))
	require.True(t, logger.hasAttr("function", "HandleProxyTCP"))

	err = client.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if err == nil {
		_, err = client.Write([]byte("x"))
	}
	require.Error(t, err)
}

type partialWriteConn struct {
	net.Conn
	written int
	err     error
}

func (c partialWriteConn) Write(p []byte) (int, error) {
	return c.written, c.err
}

func (c partialWriteConn) RemoteAddr() net.Addr {
	return testAddr("partial-remote")
}

func (c partialWriteConn) LocalAddr() net.Addr {
	return testAddr("partial-local")
}

type testAddr string

func (a testAddr) Network() string {
	return "test"
}

func (a testAddr) String() string {
	return string(a)
}
