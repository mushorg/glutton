package spice

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// SPICE link message with no caps for the main channel, sent to tcp/5907 in
// Ochi event a1089002-b561-402e-8143-7cfe51e439ac.
var scannerProbe = []byte("REDQ\x02\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00")

var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		panic(err)
	}
	return k
})

// linkMess builds a synthetic link header and message with caps.
func linkMess(connID uint32, channel uint8, common, chans []uint32) []byte {
	body := binary.LittleEndian.AppendUint32(nil, connID)
	body = append(body, channel, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(common)))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(chans)))
	body = binary.LittleEndian.AppendUint32(body, LinkMessLen)
	for _, c := range append(append([]uint32(nil), common...), chans...) {
		body = binary.LittleEndian.AppendUint32(body, c)
	}
	return append(appendHeader(nil, uint32(len(body))), body...)
}

func TestParseScannerProbe(t *testing.T) {
	require.True(t, LooksLikeSPICE(scannerProbe))
	h, err := ParseHeader(scannerProbe)
	require.NoError(t, err)
	require.Equal(t, Header{Major: 2, Minor: 2, Size: 18}, h)
	require.Equal(t, "2.2", h.Version())

	m, err := ParseLinkMess(scannerProbe[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, LinkMess{ChannelType: ChannelMain}, m)
	require.False(t, m.HasCommonCap(CapProtocolAuthSelection))
}

func TestParseLinkMessCaps(t *testing.T) {
	b := linkMess(7, 2, []uint32{0x0b}, []uint32{0x1, 0x2})
	m, err := ParseLinkMess(b[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, LinkMess{ConnectionID: 7, ChannelType: 2, CommonCaps: []uint32{0x0b}, ChannelCaps: []uint32{1, 2}}, m)
	require.True(t, m.HasCommonCap(CapProtocolAuthSelection))
	require.True(t, m.HasCommonCap(CapMiniHeader))
	require.False(t, m.HasCommonCap(CapAuthSASL))
	require.False(t, m.HasCommonCap(40))
	require.Equal(t, "0000000b", CapsHex(m.CommonCaps))
	require.Equal(t, "00000001,00000002", CapsHex(m.ChannelCaps))
}

func TestParseLinkMessRejectsCapsOutsideBody(t *testing.T) {
	b := linkMess(0, 1, []uint32{0x0b}, nil)
	body := b[HeaderLen:]
	_, err := ParseLinkMess(body[:len(body)-1])
	require.ErrorIs(t, err, ErrLinkMess)

	// caps offset inside the fixed part
	bad := append([]byte(nil), body...)
	binary.LittleEndian.PutUint32(bad[14:], 4)
	_, err = ParseLinkMess(bad)
	require.ErrorIs(t, err, ErrLinkMess)

	// huge counts must not overflow the bounds check
	bad = append([]byte(nil), body...)
	binary.LittleEndian.PutUint32(bad[6:], 0xffffffff)
	binary.LittleEndian.PutUint32(bad[10:], 0xffffffff)
	_, err = ParseLinkMess(bad)
	require.ErrorIs(t, err, ErrLinkMess)

	_, err = ParseLinkMess(body[:LinkMessLen-1])
	require.ErrorIs(t, err, ErrLinkMess)
}

func TestParseHeaderErrors(t *testing.T) {
	_, err := ParseHeader([]byte("RFB 003.008\n\x00\x00\x00\x00"))
	require.ErrorIs(t, err, ErrMagic)
	require.Equal(t, uint32(LinkErrInvalidMagic), LinkErrorFor(err))

	_, err = ParseHeader(scannerProbe[:HeaderLen-1])
	require.ErrorIs(t, err, ErrMagic)

	v1 := append([]byte(nil), scannerProbe[:HeaderLen]...)
	binary.LittleEndian.PutUint32(v1[4:], 1)
	h, err := ParseHeader(v1)
	require.ErrorIs(t, err, ErrVersion)
	require.Equal(t, "1.2", h.Version())
	require.Equal(t, uint32(LinkErrVersionMismatch), LinkErrorFor(err))

	for _, size := range []uint32{0, LinkMessLen - 1, MaxLinkMess + 1} {
		b := append([]byte(nil), scannerProbe[:HeaderLen]...)
		binary.LittleEndian.PutUint32(b[12:], size)
		_, err = ParseHeader(b)
		require.ErrorIs(t, err, ErrSize, "size %d", size)
		require.Equal(t, uint32(LinkErrInvalidData), LinkErrorFor(err))
	}
}

func TestBuildLinkReply(t *testing.T) {
	pub, err := MarshalPublicKey(&testKey().PublicKey)
	require.NoError(t, err)
	require.Len(t, pub, PubKeyLen)

	b, err := BuildLinkReply(pub, []uint32{0x0b}, []uint32{0x0f})
	require.NoError(t, err)
	require.Len(t, b, HeaderLen+linkReplyLen+8)
	r, err := ParseLinkReply(b)
	require.NoError(t, err)
	require.Equal(t, LinkReply{
		Header:      Header{Major: 2, Minor: 2, Size: linkReplyLen + 8},
		Error:       LinkErrOK,
		PubKey:      pub,
		CommonCaps:  []uint32{0x0b},
		ChannelCaps: []uint32{0x0f},
		CapsOffset:  178,
	}, r)

	_, err = BuildLinkReply(pub[:10], nil, nil)
	require.ErrorIs(t, err, ErrPubKey)
}

func TestBuildLinkError(t *testing.T) {
	b := BuildLinkError(LinkErrInvalidMagic)
	r, err := ParseLinkReply(b)
	require.NoError(t, err)
	require.Equal(t, uint32(LinkErrInvalidMagic), r.Error)
	require.Equal(t, make([]byte, PubKeyLen), r.PubKey)
	require.Empty(t, r.CommonCaps)
	require.Equal(t, uint32(linkReplyLen), r.CapsOffset)

	require.Equal(t, []byte{7, 0, 0, 0}, BuildLinkResult(LinkErrPermissionDenied))
}

func TestTicketRoundTrip(t *testing.T) {
	k := testKey()
	ct, err := EncryptTicket(&k.PublicKey, "hunter2", rand.Reader)
	require.NoError(t, err)
	require.Len(t, ct, TicketLen)
	password, err := DecryptTicket(k, ct)
	require.NoError(t, err)
	require.Equal(t, "hunter2", password)

	// an empty password is a lone NUL
	ct, err = EncryptTicket(&k.PublicKey, "", rand.Reader)
	require.NoError(t, err)
	password, err = DecryptTicket(k, ct)
	require.NoError(t, err)
	require.Empty(t, password)

	_, err = DecryptTicket(k, make([]byte, TicketLen))
	require.Error(t, err)
}

func TestNames(t *testing.T) {
	require.Equal(t, "main", ChannelTypeName(1))
	require.Equal(t, "webdav", ChannelTypeName(11))
	require.Equal(t, "42", ChannelTypeName(42))
	require.Equal(t, "PermissionDenied", LinkErrorName(LinkErrPermissionDenied))
	require.Equal(t, "99", LinkErrorName(99))
	require.Equal(t, "SPICE", AuthMechanismName(AuthSpice))
	require.Equal(t, "SASL", AuthMechanismName(AuthSASL))
	require.Equal(t, "9", AuthMechanismName(9))
	require.Empty(t, CapsHex(nil))
}
