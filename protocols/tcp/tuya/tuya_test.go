package tuya

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// DP_QUERY frame (protocol 3.3, encrypted body) captured on tcp/6668 from
// event 1 of capture run-1793918953-1.
const captureDPQueryHex = "000055aa000000000000000a000000a8" +
	"35baf5463741cbbd845fd96ff9a15aeed12dfe14e26b88ab318cfcdaeb8983fb" +
	"bf5bae5eda35466042ca059b65a007174d399e69b343694b23deddcd10619fcc" +
	"5a56e1250f388e5c2ec96f40adff8e6fa3a3857c8fb7d879f2586a07374fba2d" +
	"90070454e730385635f9249c05a859c38daecae98ce4af2a9410d6dc069da7b3" +
	"0c038f6b7032d1d1ef51307c43f66eceddb3a15cfb5dc0cd0f605ba4382b3f20" +
	"0c950a010000aa55"

func captureDPQuery(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(captureDPQueryHex)
	require.NoError(t, err)
	require.Len(t, b, 184)
	return b
}

func TestReadFrameCapturedDPQuery(t *testing.T) {
	capture := captureDPQuery(t)
	f, raw, truncated, err := ReadFrame(bytes.NewReader(capture), 4096)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, capture, raw)
	require.Equal(t, Frame{Seq: 0, Command: CmdDPQuery, Length: 0xa8, Checksum: ChecksumOK}, f)
	require.Equal(t, "dp-query", CommandName(f.Command))
}

func TestReadFrameChecksumMismatch(t *testing.T) {
	frame := captureDPQuery(t)
	frame[20] ^= 0xff
	f, _, _, err := ReadFrame(bytes.NewReader(frame), 4096)
	require.NoError(t, err)
	require.Equal(t, ChecksumMismatch, f.Checksum)
}

func TestReadFrameVersionTag(t *testing.T) {
	body := append([]byte("3.3"), make([]byte, 12)...)
	frame := BuildResponse(7, 0x0d, 0, body)
	// drop the retcode so the body starts right after the header
	frame = append(frame[:HeaderLen], frame[HeaderLen+4:]...)
	frame[15] -= 4
	f, _, _, err := ReadFrame(bytes.NewReader(frame), 4096)
	require.NoError(t, err)
	require.Equal(t, "3.3", f.Version)
	require.Equal(t, "control-new", CommandName(f.Command))
}

func TestReadFrameBadPrefix(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, raw, _, err := ReadFrame(bytes.NewReader(data), 4096)
	require.ErrorIs(t, err, ErrBadPrefix)
	require.Equal(t, data[:HeaderLen], raw)
}

func TestReadFrameBadLength(t *testing.T) {
	frame := captureDPQuery(t)[:HeaderLen]
	frame[15] = 4
	_, _, _, err := ReadFrame(bytes.NewReader(frame), 4096)
	require.ErrorIs(t, err, ErrBadLength)
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	capture := captureDPQuery(t)
	_, raw, _, err := ReadFrame(bytes.NewReader(capture[:10]), 4096)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, capture[:10], raw)
}

func TestReadFrameOversize(t *testing.T) {
	capture := captureDPQuery(t)
	_, raw, truncated, err := ReadFrame(bytes.NewReader(capture), 100)
	require.ErrorIs(t, err, ErrBodyTooLarge)
	require.True(t, truncated)
	require.Len(t, raw, HeaderLen+100)
}

func TestCommandNameUnknown(t *testing.T) {
	require.Equal(t, "cmd-0xfe", CommandName(0xfe))
}

func TestBuildResponseRoundTrip(t *testing.T) {
	resp := BuildResponse(3, CmdDPQuery, 1, UndecryptableBody)
	require.Equal(t, prefix, resp[:4])
	require.Equal(t, suffix, resp[len(resp)-4:])
	f, _, _, err := ReadFrame(bytes.NewReader(resp), 4096)
	require.NoError(t, err)
	require.Equal(t, uint32(3), f.Seq)
	require.Equal(t, CmdDPQuery, f.Command)
	require.Equal(t, uint32(4+len(UndecryptableBody)+8), f.Length)
	require.Equal(t, ChecksumOK, f.Checksum)
}
