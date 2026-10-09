package protocols

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// protocolHoneypot records the handler name of each produced TCP event.
type protocolHoneypot struct {
	produced chan string
}

func (h *protocolHoneypot) ProduceTCP(protocol string, _ net.Conn, _ connection.Metadata, _ []byte, _ interface{}) error {
	h.produced <- protocol
	return nil
}
func (h *protocolHoneypot) ProduceUDP(string, *net.UDPAddr, *net.UDPAddr, connection.Metadata, []byte, interface{}) error {
	return nil
}
func (h *protocolHoneypot) ReplyUDP(*net.UDPAddr, *net.UDPAddr, []byte) error { return nil }
func (h *protocolHoneypot) ConnectionByFlow([2]uint64) connection.Metadata {
	return connection.Metadata{}
}
func (h *protocolHoneypot) UpdateConnectionTimeout(_ context.Context, conn net.Conn) error {
	return conn.SetDeadline(time.Now().Add(2 * time.Second))
}
func (h *protocolHoneypot) GuardConn(conn net.Conn) net.Conn {
	return conn
}
func (h *protocolHoneypot) MetadataByConnection(net.Conn) (connection.Metadata, error) {
	return connection.Metadata{}, nil
}

// dispatchMCTP runs the "mctp" target on a loopback connection, lets send
// drive the client side, and returns the produced handler names.
func dispatchMCTP(t *testing.T, send func(net.Conn)) []string {
	t.Helper()
	t.Chdir(t.TempDir()) // HandleTCP stores payloads in ./payloads
	prev := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Cleanup(func() { viper.Set("max_tcp_payload", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &protocolHoneypot{produced: make(chan string, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["mctp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: 9000})
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	send(client)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	close(hp.produced)
	var names []string
	for name := range hp.produced {
		names = append(names, name)
	}
	return names
}

func TestMCTPTargetRoutesMCTP(t *testing.T) {
	names := dispatchMCTP(t, func(c net.Conn) {
		_, err := c.Write([]byte("REMOTE HI_SRDK_DEV_GetHddInfo MCTP/1.0\r\nCSeq:173\r\nContent-Length:15\r\n\r\nSegment-Num:0\r\n"))
		require.NoError(t, err)
		buf := make([]byte, 256)
		n, err := c.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "MCTP/1.0 200 OK\r\n")
	})
	require.Equal(t, []string{"mctp"}, names)
}

func TestMCTPTargetFallsBackToTCP(t *testing.T) {
	// FastCGI BEGIN_REQUEST header, as sent by PHP-FPM exploit scanners on :9000
	names := dispatchMCTP(t, func(c net.Conn) {
		_, err := c.Write([]byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		require.NoError(t, err)
		_, _ = io.ReadAll(c) // random-bytes reply until the handler closes
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestMCTPTargetShortPayloadFallsBackToTCP(t *testing.T) {
	names := dispatchMCTP(t, func(c net.Conn) {
		_, err := c.Write([]byte("REM"))
		require.NoError(t, err)
		_, _ = io.ReadAll(c)
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestMCTPTargetDelayedRequest(t *testing.T) {
	names := dispatchMCTP(t, func(c net.Conn) {
		time.Sleep(300 * time.Millisecond) // longer than the request-line peek window
		_, err := c.Write([]byte("REMOTE HI_SRDK_SYS_GetSystemAttr MCTP/1.0\r\nCSeq:1\r\nContent-Length:0\r\n\r\n"))
		require.NoError(t, err)
		buf := make([]byte, 256)
		_, err = c.Read(buf)
		require.NoError(t, err)
	})
	require.Equal(t, []string{"mctp"}, names)
}

func TestMCTPTargetSilentClientNoEvent(t *testing.T) {
	names := dispatchMCTP(t, func(net.Conn) {})
	require.Empty(t, names)
}
