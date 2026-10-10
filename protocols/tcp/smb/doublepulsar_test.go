package smb

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDoublePulsarXORRoundTrip(t *testing.T) {
	plain := []byte("MZ....This program cannot be run in DOS mode....PE\x00\x00")
	for _, seed := range []uint32{1, 0x4142, 0xffff} {
		key := DoublePulsarXORKey(seed)
		require.NotZero(t, key, "seed %#x", seed)
		cipher := XORApply(plain, key)
		require.NotEqual(t, plain, cipher)
		require.Equal(t, plain, XORApply(cipher, key), "seed %#x", seed)
	}
}

func TestDoublePulsarXORKeyDeterministic(t *testing.T) {
	// The schedule is a pure function of the seed.
	require.Equal(t, DoublePulsarXORKey(0x1234), DoublePulsarXORKey(0x1234))
	require.NotEqual(t, DoublePulsarXORKey(0x1234), DoublePulsarXORKey(0x1235))
}

func TestTrans2DataExtraction(t *testing.T) {
	data := []byte("payload-bytes")
	const dataStart = 33
	body := make([]byte, dataStart+len(data))
	body[0] = 15
	binary.LittleEndian.PutUint16(body[3:5], uint16(len(data)))            // TotalDataCount
	binary.LittleEndian.PutUint16(body[23:25], uint16(len(data)))          // DataCount
	binary.LittleEndian.PutUint16(body[25:27], uint16(32+dataStart))       // DataOffset from header
	body[27] = 1                                                           // SetupCount
	binary.LittleEndian.PutUint16(body[29:31], uint16(Trans2SessionSetup)) // Setup word
	copy(body[dataStart:], data)

	pdu := append(make([]byte, 32), body...)
	require.Equal(t, uint32(len(data)), Trans2TotalDataCount(body))
	require.Equal(t, data, Trans2Data(pdu))

	setup, ok := Trans2Setup(body)
	require.True(t, ok)
	require.Equal(t, uint16(Trans2SessionSetup), setup)
}

func TestTrans2DataShortBuffers(t *testing.T) {
	require.Zero(t, Trans2TotalDataCount([]byte{0x0f}))
	require.Nil(t, Trans2Data(make([]byte, 10)))
}
