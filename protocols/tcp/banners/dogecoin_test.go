package banners

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shodanDogecoinVersion is the Dogecoin version message a Shodan scanner sent
// to tcp/22556 on 2026-11-06: protocol 70015, zeroed addresses and user agent
// /python-dogecoin-node-check:0.1/.
func shodanDogecoinVersion(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(
		"c0c0c0c076657273696f6e0000000000" +
			"76000000a2ffcfe77f11010000000000" +
			"0000000069cdea6a0000000000000000" +
			strings.Repeat("00", 56) +
			"20" + "2f707974686f6e2d646f6765636f696e2d6e6f64652d636865636b3a302e312f" +
			"0000000000")
	require.NoError(t, err)
	require.Len(t, data, 142)
	return data
}

func TestDogecoinCapturedChecksum(t *testing.T) {
	msgs := splitNetwork(t, dogecoinNet, shodanDogecoinVersion(t))
	require.Len(t, msgs, 1)
	require.Equal(t, "version", msgs[0].command)
	require.Len(t, msgs[0].payload, 118)
}

func TestDogecoinVersionReply(t *testing.T) {
	at := time.Date(2026, 11, 6, 22, 29, 35, 0, time.UTC)
	stubBitcoin(t, at, 0x0102030405060708)
	data := shodanDogecoinVersion(t)

	// the other networks' matchers leave Dogecoin traffic alone
	_, ok := bitcoinReply(data)
	require.False(t, ok)
	_, ok = litecoinReply(data)
	require.False(t, ok)
	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, "dogecoin-version", resp.Name)

	msgs := splitNetwork(t, dogecoinNet, resp.Data)
	require.Len(t, msgs, 2)
	require.Equal(t, "version", msgs[0].command)
	require.Equal(t, "verack", msgs[1].command)

	v := msgs[0].payload
	le := binary.LittleEndian
	require.Equal(t, uint32(70015), le.Uint32(v[0:4]))
	require.Equal(t, uint64(1|4), le.Uint64(v[4:12]))
	require.Equal(t, uint64(at.Unix()), le.Uint64(v[12:20]))
	require.Equal(t, uint64(0x0102030405060708), le.Uint64(v[72:80]))
	require.Equal(t, byte(len(dogecoinNet.userAgent)), v[80])
	require.Equal(t, "/Shibetoshi:1.14.9/", string(v[81:81+len(dogecoinNet.userAgent)]))
	height := le.Uint32(v[len(v)-5 : len(v)-1])
	require.Equal(t, uint32(5000000+(at.Unix()-1703116800)/60), height)
	require.InDelta(t, 6_500_000, height, 30_000)
}

func TestDogecoinFollowUps(t *testing.T) {
	stubBitcoin(t, time.Unix(1760000000, 0), 1)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	resp, ok := ForPayload(btcFrame(dogecoinNet, "ping", nonce))
	require.True(t, ok)
	require.Equal(t, Response{Name: "dogecoin-ping", Data: btcFrame(dogecoinNet, "pong", nonce)}, resp)

	resp, ok = ForPayload(btcFrame(dogecoinNet, "verack", nil))
	require.True(t, ok)
	require.Equal(t, Response{Name: "dogecoin-verack", NoReply: true}, resp)
}
