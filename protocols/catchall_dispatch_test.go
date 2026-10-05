package protocols

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
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
