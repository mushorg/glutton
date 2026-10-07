package dnp3

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// Frames captured from an internet-wide DNP3 sweep (Ochi event
// 91245d5a-7032-4cce-a34e-1ff48b62118e): REQUEST_LINK_STATUS from 3 to 0..2.
var capturedFrames = [][]byte{
	{0x05, 0x64, 0x05, 0xc9, 0x52, 0x00, 0x02, 0x00, 0x33, 0x3e},
	{0x05, 0x64, 0x05, 0xc9, 0x53, 0x00, 0x02, 0x00, 0xdb, 0xfc},
	{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x03, 0x00, 0x9d, 0xfc},
	{0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x03, 0x00, 0x75, 0x3e},
}

func TestCRC(t *testing.T) {
	for _, f := range capturedFrames {
		require.Equal(t, binary.LittleEndian.Uint16(f[8:]), CRC(f[:8]))
	}
	require.Equal(t, uint16(0xffff), CRC(nil))
}

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader(capturedFrames[2])
	require.NoError(t, err)
	require.Equal(t, Header{Length: 5, Control: 0xc9, Dest: 0, Src: 3}, h)
	require.True(t, h.DIR())
	require.True(t, h.PRM())
	require.Equal(t, byte(FuncRequestLinkStatus), h.Function())
	require.Equal(t, "REQUEST_LINK_STATUS", h.Command())
	require.Equal(t, 0, h.BodySize())
}

func TestParseHeaderErrors(t *testing.T) {
	_, err := ParseHeader(capturedFrames[0][:9])
	require.ErrorIs(t, err, ErrShort)

	bad := append([]byte(nil), capturedFrames[0]...)
	bad[0] = 0x06
	_, err = ParseHeader(bad)
	require.ErrorIs(t, err, ErrStart)

	bad = append([]byte(nil), capturedFrames[0]...)
	bad[9] ^= 0xff
	_, err = ParseHeader(bad)
	require.ErrorIs(t, err, ErrHeaderCRC)

	short := []byte{0x05, 0x64, 0x04, 0xc9, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(short[8:], CRC(short[:8]))
	_, err = ParseHeader(short)
	require.ErrorIs(t, err, ErrLength)
}

func TestBodySize(t *testing.T) {
	for length, want := range map[byte]int{5: 0, 6: 3, 21: 18, 22: 21, 255: 250 + 2*16} {
		require.Equal(t, want, Header{Length: length}.BodySize(), "length %d", length)
	}
}

func dataFrameBody(user []byte) []byte {
	var body []byte
	for len(user) > 0 {
		n := min(len(user), blockSize)
		body = append(body, user[:n]...)
		body = binary.LittleEndian.AppendUint16(body, CRC(user[:n]))
		user = user[n:]
	}
	return body
}

func TestUserData(t *testing.T) {
	user := make([]byte, 20)
	for i := range user {
		user[i] = byte(i)
	}
	h := Header{Length: byte(MinLength + len(user))}
	body := dataFrameBody(user)
	require.Len(t, body, h.BodySize())

	got, err := h.UserData(body)
	require.NoError(t, err)
	require.Equal(t, user, got)

	body[17] ^= 0xff // corrupt the second block
	_, err = h.UserData(body)
	require.ErrorIs(t, err, ErrDataCRC)

	_, err = h.UserData(body[:5])
	require.ErrorIs(t, err, ErrShort)
}

func TestSecondary(t *testing.T) {
	// LINK_STATUS from outstation 10 to master 3.
	got := Secondary(FuncLinkStatus, 3, 10)
	require.Equal(t, []byte{0x05, 0x64, 0x05, 0x0b, 0x03, 0x00, 0x0a, 0x00}, got[:8])
	h, err := ParseHeader(got)
	require.NoError(t, err)
	require.False(t, h.DIR())
	require.False(t, h.PRM())
	require.Equal(t, "LINK_STATUS", h.Command())
}

func TestReply(t *testing.T) {
	req := func(control byte, dest, src uint16) Header {
		return Header{Length: 5, Control: control, Dest: dest, Src: src}
	}
	const own = 10

	require.Equal(t, Secondary(FuncLinkStatus, 3, own), Reply(req(0xc9, own, 3), own))
	require.Equal(t, Secondary(FuncACK, 3, own), Reply(req(0xc2, own, 3), own)) // TEST_LINK_STATES
	require.Equal(t, Secondary(FuncACK, 3, own), Reply(req(0xc0, own, 3), own)) // RESET_LINK_STATES
	require.Equal(t, Secondary(FuncACK, 3, own), Reply(req(0xc3, own, 3), own)) // CONFIRMED_USER_DATA
	require.Nil(t, Reply(req(0xc4, own, 3), own))                               // UNCONFIRMED_USER_DATA
	require.Equal(t, Secondary(FuncNotSupported, 3, own), Reply(req(0xc5, own, 3), own))
	require.Nil(t, Reply(req(0xc9, own+1, 3), own))  // other station
	require.Nil(t, Reply(req(0xc9, 0xffff, 3), own)) // broadcast
	require.Nil(t, Reply(req(0x49, own, 3), own))    // DIR=0
	require.Nil(t, Reply(req(0x89, own, 3), own))    // PRM=0
}
