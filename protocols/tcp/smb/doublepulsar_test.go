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

func TestDoublePulsarOpcode(t *testing.T) {
	require.Equal(t, byte(DPOpExec), DoublePulsarOpcode(0x61056200))
	require.Equal(t, byte(DPOpPing), DoublePulsarOpcode(0x00000023))
	require.Equal(t, byte(DPOpKill), DoublePulsarOpcode(0x00000077))
}

func TestTrans2Timeout(t *testing.T) {
	body := make([]byte, 30)
	binary.LittleEndian.PutUint32(body[13:], 0x61056200)
	require.Equal(t, uint32(0x61056200), Trans2Timeout(body))
	require.Zero(t, Trans2Timeout(body[:10]))
}

func TestDoublePulsarXORKey64Vector(t *testing.T) {
	const sig = 0x018d2d0a6f
	require.Equal(t, uint32(0x75503953), DoublePulsarXORKey64(sig))
	require.True(t, DoublePulsarArchX64(sig))
	require.False(t, DoublePulsarArchX64(0x2d0a6f))
	require.Equal(t, DoublePulsarXORKey(0x1234), DoublePulsarXORKey64(0x1234))
}

func TestVariantString(t *testing.T) {
	require.Equal(t, "clean", Clean.String())
	require.Equal(t, "infected", Infected.String())
	require.Equal(t, Clean, Variants[0])
}

func TestMakeDoublePulsarPingResponse(t *testing.T) {
	req := SMBHeader{Command: CmdTransaction2}
	binary.LittleEndian.PutUint16(req.MID[:], 0x41)
	sig := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	h, data, err := MakeDoublePulsarPingResponse(req, sig)
	require.NoError(t, err)
	require.Equal(t, uint16(0x51), binary.LittleEndian.Uint16(h.MID[:]))
	require.Equal(t, sig[:], data[14:22])
	require.Equal(t, []byte{0x51, 0x00}, data[30:32])
	require.Zero(t, NTStatus(h))
}
