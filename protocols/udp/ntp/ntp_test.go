package ntp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Captured monlist probe on udp/123
// (Ochi event 55bbf2fb-5298-4c11-9d1a-0ff70f5a0e80): mode 7, VN 2, impl 3, req 42.
func monlist() []byte {
	return append([]byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}, make([]byte, 184)...)
}

func clientPacket() []byte {
	b := make([]byte, PacketLen)
	b[0] = 0x1b // LI 0, VN 3, mode 3
	b[2] = 6
	binary.BigEndian.PutUint64(b[40:], 0xdeadbeef01020304)
	return b
}

func TestParseMonlist(t *testing.T) {
	p, err := Parse(monlist())
	require.NoError(t, err)
	require.Equal(t, ModePrivate, p.Mode)
	require.Equal(t, 2, p.Version)
	require.Equal(t, 3, p.Impl)
	require.Equal(t, 42, p.ReqCode)
	require.Equal(t, "mon_getlist_1", p.Command())
	require.True(t, LooksLikeNTP(monlist()))
}

func TestParseControl(t *testing.T) {
	b := []byte{0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0} // VN 2 mode 6 READVAR
	p, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, "readvar", p.Command())
	require.Equal(t, 1, p.Sequence)
	require.True(t, LooksLikeNTP(b))
}

func TestParseClient(t *testing.T) {
	p, err := Parse(clientPacket())
	require.NoError(t, err)
	require.Equal(t, "client", p.Command())
	require.Equal(t, 3, p.Version)
	require.Equal(t, 6, p.Poll)
	require.True(t, LooksLikeNTP(clientPacket()))
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(nil)
	require.ErrorIs(t, err, ErrShort)
	_, err = Parse([]byte{0x17, 0, 3})
	require.ErrorIs(t, err, ErrShort)
	_, err = Parse(make([]byte, 48)) // mode 0
	require.ErrorIs(t, err, ErrMode)
	_, err = Parse([]byte{0x1b, 0, 0})
	require.ErrorIs(t, err, ErrShort)
}

func TestLooksLikeNTPNegative(t *testing.T) {
	require.False(t, LooksLikeNTP(nil))
	require.False(t, LooksLikeNTP([]byte("GET / HTTP/1.1\r\n")))
	require.False(t, LooksLikeNTP(make([]byte, 48)))
	require.False(t, LooksLikeNTP(clientPacket()[:47]))
	bad := monlist()
	bad[2] = 9 // unknown implementation
	require.False(t, LooksLikeNTP(bad))
	resp := monlist()
	resp[0] |= 0x80 // response bit
	require.False(t, LooksLikeNTP(resp))
	unknown := monlist()
	unknown[3] = 200
	require.False(t, LooksLikeNTP(unknown))
}

func TestBuildResponseNeverAmplifies(t *testing.T) {
	now := time.Unix(1_700_000_000, 500_000_000)
	ref := [4]byte{1, 2, 3, 4}
	for _, req := range [][]byte{monlist(), clientPacket(), {0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}} {
		p, err := Parse(req)
		require.NoError(t, err)
		resp := BuildResponse(p, req, now, ref)
		require.NotNil(t, resp)
		require.LessOrEqual(t, len(resp), len(req))
	}
}

func TestBuildServerReply(t *testing.T) {
	req := clientPacket()
	p, _ := Parse(req)
	now := time.Unix(1_700_000_000, 0)
	resp := BuildResponse(p, req, now, [4]byte{9, 9, 9, 9})
	require.Len(t, resp, PacketLen)
	require.Equal(t, byte(0x1c), resp[0]) // VN 3, mode 4
	require.Equal(t, byte(2), resp[1])
	require.Equal(t, byte(6), resp[2])
	require.Equal(t, []byte{9, 9, 9, 9}, resp[12:16])
	require.True(t, bytes.Equal(req[40:48], resp[24:32]), "origin echoes client transmit")
	require.Equal(t, uint64(1_700_000_000+ntpEpochOffset), binary.BigEndian.Uint64(resp[32:40])>>32)
}

func TestBuildPrivateError(t *testing.T) {
	req := monlist()
	p, _ := Parse(req)
	resp := BuildResponse(p, req, time.Now(), [4]byte{})
	require.Equal(t, []byte{0x97, 0x00, 0x03, 0x2a, 0x20, 0x00, 0x00, 0x00}, resp)
}

func TestBuildNoReplyForResponsesAndPeers(t *testing.T) {
	req := monlist()
	req[0] |= 0x80
	p, _ := Parse(req)
	require.Nil(t, BuildResponse(p, req, time.Now(), [4]byte{}))
	peer := clientPacket()
	peer[0] = 0x1b&^7 | ModeSymActive
	p, _ = Parse(peer)
	require.Nil(t, BuildResponse(p, peer, time.Now(), [4]byte{}))
}
