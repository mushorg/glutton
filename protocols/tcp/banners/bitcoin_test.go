package banners

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// xpanseVersion is the Bitcoin version message from Ochi event
// d268c172-a0c7-4e2f-9277-be1d97cc7b86 (tcp/8333): protocol 40000, a fixed
// 2024-04-10 timestamp, empty user agent and start height 0.
const xpanseVersion = "f9beb4d976657273696f6e000000000055000000cdea8e08409c00000100000000000000" +
	"dea61666000000000100000000000000578b7fa2000000000000000000000000208d0100" +
	"0000000000000a96000a000000000000000000000000afa852734183843401a100000000" +
	"00"

func stubBitcoin(t *testing.T, at time.Time, nonce uint64) {
	t.Helper()
	prevNow, prevNonce := now, bitcoinNonce
	now = func() time.Time { return at }
	bitcoinNonce = func() uint64 { return nonce }
	t.Cleanup(func() { now, bitcoinNonce = prevNow, prevNonce })
}

// splitBitcoin parses a reply into its messages, checking magic, length and
// checksum of each.
func splitBitcoin(t *testing.T, data []byte) []btcMessage {
	t.Helper()
	return splitNetwork(t, bitcoinNet, data)
}

func splitNetwork(t *testing.T, n btcNetwork, data []byte) []btcMessage {
	t.Helper()
	var msgs []btcMessage
	for len(data) > 0 {
		require.GreaterOrEqual(t, len(data), btcHeaderLen)
		require.Equal(t, n.magic, data[:4])
		command, ok := btcCommand(data[4:16])
		require.True(t, ok)
		length := int(binary.LittleEndian.Uint32(data[16:20]))
		require.GreaterOrEqual(t, len(data), btcHeaderLen+length)
		payload := data[btcHeaderLen : btcHeaderLen+length]
		sum := sha256.Sum256(payload)
		sum = sha256.Sum256(sum[:])
		require.Equal(t, sum[:4], data[20:24], "checksum of %s", command)
		msgs = append(msgs, btcMessage{command: command, payload: payload})
		data = data[btcHeaderLen+length:]
	}
	return msgs
}

func TestBitcoinCapturedChecksum(t *testing.T) {
	data, err := hex.DecodeString(xpanseVersion)
	require.NoError(t, err)
	msgs := splitBitcoin(t, data)
	require.Len(t, msgs, 1)
	require.Equal(t, "version", msgs[0].command)
	require.Len(t, msgs[0].payload, 85)
}

func TestBitcoinVersionReply(t *testing.T) {
	at := time.Date(2026, 10, 11, 13, 9, 8, 0, time.UTC)
	stubBitcoin(t, at, 0x0102030405060708)
	data, err := hex.DecodeString(xpanseVersion)
	require.NoError(t, err)

	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, "bitcoin-version", resp.Name)
	require.False(t, resp.NoReply)

	msgs := splitBitcoin(t, resp.Data)
	require.Len(t, msgs, 2)
	require.Equal(t, "version", msgs[0].command)
	require.Equal(t, btcMessage{command: "verack", payload: []byte{}}, msgs[1])
	// empty-payload checksum
	require.Equal(t, []byte{0x5d, 0xf6, 0xe0, 0xe2}, resp.Data[len(resp.Data)-4:])

	v := msgs[0].payload
	require.Len(t, v, 4+8+8+26+26+8+1+len(bitcoinNet.userAgent)+4+1)
	le := binary.LittleEndian
	require.Equal(t, uint32(70016), le.Uint32(v[0:4]))
	require.Equal(t, uint64(0x409), le.Uint64(v[4:12]))
	require.Equal(t, uint64(at.Unix()), le.Uint64(v[12:20]))
	require.Equal(t, make([]byte, 26), v[20:46])
	require.Equal(t, uint64(0x409), le.Uint64(v[46:54]))
	require.Equal(t, make([]byte, 18), v[54:72])
	require.Equal(t, uint64(0x0102030405060708), le.Uint64(v[72:80]))
	require.Equal(t, byte(len(bitcoinNet.userAgent)), v[80])
	require.Equal(t, "/Satoshi:28.1.0/", string(v[81:97]))
	require.Equal(t, uint32(840000+(at.Unix()-1713571767)/600), le.Uint32(v[97:101]))
	require.Equal(t, byte(1), v[101])
}

func TestBitcoinStartHeightNotBeforeAnchor(t *testing.T) {
	stubBitcoin(t, time.Unix(0, 0), 1)
	v := btcVersion(bitcoinNet)
	require.Equal(t, uint32(bitcoinNet.anchorHeight), binary.LittleEndian.Uint32(v[97:101]))
}

func TestBitcoinFollowUps(t *testing.T) {
	stubBitcoin(t, time.Unix(1760000000, 0), 1)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	resp, ok := ForPayload(btcFrame(bitcoinNet, "ping", nonce))
	require.True(t, ok)
	require.Equal(t, Response{Name: "bitcoin-ping", Data: btcFrame(bitcoinNet, "pong", nonce)}, resp)

	// verack and getaddr in one segment: nothing to answer, keep the connection
	resp, ok = ForPayload(append(btcFrame(bitcoinNet, "verack", nil), btcFrame(bitcoinNet, "getaddr", nil)...))
	require.True(t, ok)
	require.Equal(t, Response{Name: "bitcoin-verack", NoReply: true}, resp)

	// unknown command, valid header
	resp, ok = ForPayload(btcFrame(bitcoinNet, "foo", nil))
	require.True(t, ok)
	require.Equal(t, Response{Name: "bitcoin", NoReply: true}, resp)

	// pre-BIP31 ping without a nonce gets no pong
	resp, ok = ForPayload(btcFrame(bitcoinNet, "ping", nil))
	require.True(t, ok)
	require.True(t, resp.NoReply)

	// version then ping in one segment answers both in order
	resp, ok = ForPayload(append(btcFrame(bitcoinNet, "version", make([]byte, 85)), btcFrame(bitcoinNet, "ping", nonce)...))
	require.True(t, ok)
	msgs := splitBitcoin(t, resp.Data)
	require.Len(t, msgs, 3)
	require.Equal(t, []string{"version", "verack", "pong"}, []string{msgs[0].command, msgs[1].command, msgs[2].command})
}

func TestBitcoinTruncatedPayloadStillMatches(t *testing.T) {
	data, err := hex.DecodeString(xpanseVersion)
	require.NoError(t, err)
	resp, ok := ForPayload(data[:40])
	require.True(t, ok)
	require.Equal(t, "bitcoin-version", resp.Name)
}

func TestBitcoinNoMatch(t *testing.T) {
	data, err := hex.DecodeString(xpanseVersion)
	require.NoError(t, err)
	testnet := append([]byte{0x0b, 0x11, 0x09, 0x07}, data[4:]...)
	badCmd := append([]byte{}, data...)
	badCmd[13] = 'x' // byte after the NUL terminator
	unprintable := append([]byte{}, data...)
	unprintable[4] = 0x01
	emptyCmd := append([]byte{}, data...)
	copy(emptyCmd[4:16], make([]byte, 12))
	huge := append([]byte{}, data...)
	binary.LittleEndian.PutUint32(huge[16:20], btcMaxPayload+1)

	for name, d := range map[string][]byte{
		"short header": data[:23],
		"testnet":      testnet,
		"padding":      badCmd,
		"unprintable":  unprintable,
		"empty cmd":    emptyCmd,
		"oversize":     huge,
		"http":         []byte("GET / HTTP/1.0\r\n\r\n"),
	} {
		_, ok := bitcoinReply(d)
		require.False(t, ok, name)
	}
}
