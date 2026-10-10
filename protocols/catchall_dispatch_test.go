package protocols

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/protocols/tcp/banners"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestCatchAllSendsBannerWithoutClientData(t *testing.T) {
	t.Chdir(t.TempDir())
	prev := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Cleanup(func() { viper.Set("max_tcp_payload", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &protocolHoneypot{produced: make(chan string, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["tcp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: 22})
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	// well under the 2s idle deadline: the banner must not wait for client bytes
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", line)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	require.Equal(t, "tcp", <-hp.produced)
}

// startCatchAllDispatch serves one connection on port through the catch-all
// dispatcher with a short greet wait.
func startCatchAllDispatch(t *testing.T, port uint16) (net.Conn, *protocolHoneypot, chan error) {
	t.Helper()
	t.Chdir(t.TempDir())
	prevMax := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	prevWait := greetWait
	greetWait = 100 * time.Millisecond
	t.Cleanup(func() {
		viper.Set("max_tcp_payload", prevMax)
		greetWait = prevWait
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	hp := &protocolHoneypot{produced: make(chan string, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["tcp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: port})
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func finishCatchAllDispatch(t *testing.T, client net.Conn, hp *protocolHoneypot, done chan error) string {
	t.Helper()
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	select {
	case protocol := <-hp.produced:
		return protocol
	case <-time.After(time.Second):
		t.Fatal("no event produced")
	}
	return ""
}

func TestCatchAllGreetsSilentClientOnIdlePort(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 4444)

	want, _ := banners.ForPort(4444)
	got := make([]byte, len(want.Data))
	_, err := io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, want.Data, got)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllIdlePortClientFirstNotGreeted(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 4444)

	_, err := client.Write([]byte("whoami\r\n"))
	require.NoError(t, err)
	// one prompt as the reply, no greeting before it
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	want, _ := banners.ForPort(4444)
	require.Equal(t, want.Data, reply)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func enableSpicy(t *testing.T) {
	t.Helper()
	if err := spicy.Initialize(nopLogger{}); err != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", err)
	}
	prev := viper.GetBool("spicy.enabled")
	viper.Set("spicy.enabled", true)
	t.Cleanup(func() { viper.Set("spicy.enabled", prev) })
}

func TestCatchAllIdlePortRoutesHTTP(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 4444)

	// shorter than the 96-byte MCP peek: the request must not be lost
	_, err := client.Write([]byte("GET /wd/hub/status HTTP/1.1\r\nHost: 192.0.2.1:4444\r\n\r\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(line, "HTTP/1.1 "), "%q", line)

	require.Equal(t, "http", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllShortPayloadWithSpicy(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 4444)

	// shorter than the 16-byte protocol peek: still handled, not dropped
	_, err := client.Write([]byte("whoami\r\n"))
	require.NoError(t, err)
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	want, _ := banners.ForPort(4444)
	require.Equal(t, want.Data, reply)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllLongPayloadWithSpicy(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 9999)

	// past the 16-byte protocol peek: the bytes must reach HandleTCP, which
	// answers with random bytes
	_, err := client.Write([]byte("\x10\x20\x30\x40 not a known protocol at all\r\n"))
	require.NoError(t, err)
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	require.NotEmpty(t, reply)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}
