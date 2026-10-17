package radius

import (
	"crypto/md5" //nolint:gosec
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured infrawatch Access-Request (Ochi event 48449bf5-270b-4ba6-a200-480ca094afb4).
var captured = []byte{
	0x01, 0xbc, 0x00, 0x50, 0x2a, 0xf2, 0xd1, 0x31, 0x64, 0x51, 0x20, 0x8b, 0x93, 0xee, 0xdb, 0x85,
	0x37, 0x86, 0xba, 0x26, 0x01, 0x3c, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x67, 0x72, 0x61, 0x62, 0x2d,
	0x32, 0x61, 0x66, 0x32, 0x64, 0x31, 0x33, 0x31, 0x36, 0x34, 0x35, 0x31, 0x32, 0x30, 0x38, 0x62,
	0x39, 0x33, 0x65, 0x65, 0x64, 0x62, 0x38, 0x35, 0x33, 0x37, 0x38, 0x36, 0x62, 0x61, 0x32, 0x36,
	0x40, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64,
}

func TestParseCaptured(t *testing.T) {
	p, err := Parse(captured)
	require.NoError(t, err)
	require.Equal(t, byte(CodeAccessRequest), p.Code)
	require.Equal(t, byte(0xbc), p.ID)
	require.Equal(t, 80, p.Length)
	user, ok := p.Find(AttrUserName)
	require.True(t, ok)
	require.Equal(t, "infragrab-2af2d1316451208b93eedb853786ba26@invalid.invalid", string(user))
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(captured[:19])
	require.ErrorIs(t, err, ErrShort)

	over := append([]byte(nil), captured...)
	over[3] = 0xff // length 255 > datagram
	_, err = Parse(over)
	require.ErrorIs(t, err, ErrLength)

	under := append([]byte(nil), captured...)
	under[3] = 19
	_, err = Parse(under)
	require.ErrorIs(t, err, ErrLength)

	huge := append([]byte(nil), captured...)
	huge[2], huge[3] = 0x20, 0x00 // 8192 > 4096
	_, err = Parse(huge)
	require.ErrorIs(t, err, ErrLength)

	bad := append([]byte(nil), captured...)
	bad[21] = 0x01 // attribute length < 2
	p, err := Parse(bad)
	require.ErrorIs(t, err, ErrAttr)
	require.Equal(t, byte(CodeAccessRequest), p.Code)

	bad[21] = 0xff // attribute longer than the remaining body
	_, err = Parse(bad)
	require.ErrorIs(t, err, ErrAttr)
}

func TestParseIgnoresTrailingBytes(t *testing.T) {
	p, err := Parse(append(append([]byte(nil), captured...), 0xde, 0xad))
	require.NoError(t, err)
	require.Len(t, p.Attrs, 1)
}

func TestReply(t *testing.T) {
	p, err := Parse(captured)
	require.NoError(t, err)
	resp := Reply(p)
	require.Len(t, resp, 20)
	require.Equal(t, []byte{CodeAccessReject, 0xbc, 0x00, 0x14}, resp[:4])

	hdr := append([]byte{CodeAccessReject, 0xbc, 0x00, 0x14}, captured[4:20]...)
	sum := md5.Sum(append(hdr, replySecret...)) //nolint:gosec
	require.Equal(t, sum[:], resp[4:])

	p.Code = CodeAccountingRequest
	require.Equal(t, byte(CodeAccountingResponse), Reply(p)[0])
	p.Code = CodeStatusServer
	require.Equal(t, byte(CodeAccessAccept), Reply(p)[0])
	p.Code = CodeAccessAccept
	require.Nil(t, Reply(p))
}

func hide(secret, password string, auth [16]byte) []byte {
	pw := []byte(password)
	for len(pw)%16 != 0 {
		pw = append(pw, 0)
	}
	var out []byte
	prev := auth[:]
	for i := 0; i < len(pw); i += 16 {
		sum := md5.Sum(append([]byte(secret), prev...)) //nolint:gosec
		blk := make([]byte, 16)
		for j := range blk {
			blk[j] = pw[i+j] ^ sum[j]
		}
		out = append(out, blk...)
		prev = blk
	}
	return out
}

func TestDecryptPassword(t *testing.T) {
	var auth [16]byte
	copy(auth[:], captured[4:20])
	pw, ok := DecryptPassword(auth, hide("testing123", "admin", auth))
	require.True(t, ok)
	require.Equal(t, "admin", pw)

	long := "a-password-longer-than-sixteen"
	pw, ok = DecryptPassword(auth, hide("secret", long, auth))
	require.True(t, ok)
	require.Equal(t, long, pw)

	_, ok = DecryptPassword(auth, hide("unknown-secret", "admin", auth))
	require.False(t, ok)
	_, ok = DecryptPassword(auth, []byte{1, 2, 3})
	require.False(t, ok)
}

func TestCodeName(t *testing.T) {
	require.Equal(t, "Access-Request", CodeName(1))
	require.Equal(t, "code_99", CodeName(99))
}
