package tcp

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Captured Shodan probe on tcp/8545 (python-requests/2.23.0).
const ethWeb3ClientVersionProbe = `{"params": [], "jsonrpc": "2.0", "method": "web3_clientVersion", "id": 67}`

func TestHandleEthereumRPC(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "web3_clientVersion",
			body: ethWeb3ClientVersionProbe,
			want: `{"jsonrpc":"2.0","id":67,"result":"Geth/LVIV/v1.0.0/linux/go1.4.2"}`,
		},
		{
			name: "eth_blockNumber",
			body: `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`,
			want: `{"jsonrpc":"2.0","id":1,"result":"0x4b7"}`,
		},
		{
			name: "string id echoed",
			body: `{"jsonrpc":"2.0","method":"eth_accounts","id":"abc"}`,
			want: `{"jsonrpc":"2.0","id":"abc","result":["0x407d73d8a49eeb85d32cf465507dd71d507100c1"]}`,
		},
		{
			name: "unknown method",
			body: `{"jsonrpc":"2.0","method":"net_peerCount","id":7}`,
			want: `{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"the method net_peerCount does not exist/is not available"}}`,
		},
		{
			name: "batch",
			body: `[{"jsonrpc":"2.0","method":"eth_blockNumber","id":1},{"jsonrpc":"2.0","method":"web3_clientVersion","id":2}]`,
			want: `[{"jsonrpc":"2.0","id":1,"result":"0x4b7"},{"jsonrpc":"2.0","id":2,"result":"Geth/LVIV/v1.0.0/linux/go1.4.2"}]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handleEthereumRPC([]byte(tt.body))
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestIsEthereumRPC(t *testing.T) {
	require.True(t, isEthereumRPC([]byte(ethWeb3ClientVersionProbe)))
	require.True(t, isEthereumRPC([]byte(`{"method":"eth_blockNumber","id":1}`)))
	require.True(t, isEthereumRPC([]byte(` [{"method":"net_version","id":1}]`)))
	require.False(t, isEthereumRPC([]byte(`{"method":"tools/list","id":1}`)))
	require.False(t, isEthereumRPC([]byte(`user=eth_blockNumber`)))
	require.False(t, isEthereumRPC(nil))
}

func TestHandleHTTPEthereumClientVersion(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{TargetPort: 8545}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("POST", "/", "", []byte(ethWeb3ClientVersionProbe)))
	require.NoError(t, err)
	status, _, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.JSONEq(t, `{"jsonrpc":"2.0","id":67,"result":"Geth/LVIV/v1.0.0/linux/go1.4.2"}`, string(body))

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "POST", events[0].Command)
	require.Equal(t, "/", events[0].Path)
	require.Contains(t, string(events[0].Payload), "web3_clientVersion")
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
	require.Contains(t, string(events[1].Payload), clientVersion)
}
