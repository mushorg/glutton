package banners

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shodanLitecoinVersion is the Litecoin version message from Ochi event
// ea2e84f5-88a2-4f65-b5df-dc174015d98e (tcp/9333): protocol 70015, zeroed
// addresses and user agent /python-litecoin-node-check:0.1/.
func shodanLitecoinVersion(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(
		"fbc0b6db76657273696f6e0000000000" +
			"76000000e9ae4a1d7f11010000000000" +
			"00000000cebfd36a0000000000000000" +
			strings.Repeat("00", 56) +
			"20" + "2f707974686f6e2d6c697465636f696e2d6e6f64652d636865636b3a302e312f" +
			"0000000000")
	require.NoError(t, err)
	require.Len(t, data, 142)
	return data
}

func TestLitecoinCapturedChecksum(t *testing.T) {
	msgs := splitNetwork(t, litecoinNet, shodanLitecoinVersion(t))
	require.Len(t, msgs, 1)
	require.Equal(t, "version", msgs[0].command)
	require.Len(t, msgs[0].payload, 118)
}

func TestLitecoinVersionReply(t *testing.T) {
	at := time.Date(2026, 10, 17, 18, 38, 29, 0, time.UTC)
	stubBitcoin(t, at, 0x0102030405060708)
	data := shodanLitecoinVersion(t)

	// each network's matcher leaves the other's traffic alone
	_, ok := bitcoinReply(data)
	require.False(t, ok)
	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, "litecoin-version", resp.Name)

	msgs := splitNetwork(t, litecoinNet, resp.Data)
	require.Len(t, msgs, 2)
	require.Equal(t, "version", msgs[0].command)
	require.Equal(t, "verack", msgs[1].command)

	v := msgs[0].payload
	le := binary.LittleEndian
	require.Equal(t, uint32(70015), le.Uint32(v[0:4]))
	require.Equal(t, uint64(1|8|1024|1<<24), le.Uint64(v[4:12]))
	require.Equal(t, uint64(at.Unix()), le.Uint64(v[12:20]))
	require.Equal(t, uint64(0x0102030405060708), le.Uint64(v[72:80]))
	require.Equal(t, byte(len(litecoinNet.userAgent)), v[80])
	require.Equal(t, "/LitecoinCore:0.21.4/", string(v[81:81+len(litecoinNet.userAgent)]))
	height := le.Uint32(v[len(v)-5 : len(v)-1])
	require.Equal(t, uint32(2520000+(at.Unix()-1690977600)/150), height)
	require.InDelta(t, 3_190_000, height, 30_000)
}

func TestLitecoinFollowUps(t *testing.T) {
	stubBitcoin(t, time.Unix(1760000000, 0), 1)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	resp, ok := ForPayload(btcFrame(litecoinNet, "ping", nonce))
	require.True(t, ok)
	require.Equal(t, Response{Name: "litecoin-ping", Data: btcFrame(litecoinNet, "pong", nonce)}, resp)

	resp, ok = ForPayload(btcFrame(litecoinNet, "foo", nil))
	require.True(t, ok)
	require.Equal(t, Response{Name: "litecoin", NoReply: true}, resp)

	// a Bitcoin message keeps its own name and magic
	resp, ok = ForPayload(btcFrame(bitcoinNet, "ping", nonce))
	require.True(t, ok)
	require.Equal(t, Response{Name: "bitcoin-ping", Data: btcFrame(bitcoinNet, "pong", nonce)}, resp)
}
