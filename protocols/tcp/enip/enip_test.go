package enip

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// censysListIdentity is the request from Ochi event
// e5ed3dc4-7163-46f6-b370-3ca529d487de (sender context "OISYSNEC").
var censysListIdentity = []byte{
	0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x49, 0x53, 0x59,
	0x53, 0x4e, 0x45, 0x43, 0x00, 0x00, 0x00, 0x00,
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader(censysListIdentity)
	require.NoError(t, err)
	require.Equal(t, uint16(CmdListIdentity), h.Command)
	require.Zero(t, h.Length)
	require.Zero(t, h.SessionHandle)
	require.Equal(t, "OISYSNEC", string(h.SenderContext[:]))
	require.Equal(t, censysListIdentity, h.Marshal(nil))

	_, err = ParseHeader(censysListIdentity[:10])
	require.ErrorIs(t, err, ErrShort)
}

func TestListIdentityReply(t *testing.T) {
	req, err := ParseHeader(censysListIdentity)
	require.NoError(t, err)
	id := DefaultIdentity
	id.SerialNumber = 0x11223344

	got := ListIdentityReply(req, id, net.IPv4(10, 0, 0, 5), 44818)
	want := mustDecodeHex(t, ""+
		"6300"+"3300"+"00000000"+"00000000"+"4f495359534e4543"+"00000000"+ // header, length 51
		"0100"+"0c00"+"2d00"+ // one Identity item, 45 bytes
		"0100"+"0002"+"af12"+"0a000005"+"0000000000000000"+ // version 1, sockaddr 10.0.0.5:44818
		"0100"+"0c00"+"a600"+"0b02"+"3000"+"44332211"+ // vendor 1, type 12, code 166, rev 11.2, status, serial
		"0b"+hex.EncodeToString([]byte("1756-EN2T/D"))+"03")
	require.Equal(t, want, got)

	h, err := ParseHeader(got)
	require.NoError(t, err)
	require.Equal(t, int(h.Length), len(got)-HeaderSize)
}

func TestListServicesReply(t *testing.T) {
	req, _ := ParseHeader(censysListIdentity)
	req.Command = CmdListServices
	got := ListServicesReply(req)
	want := mustDecodeHex(t, ""+
		"0400"+"1a00"+"00000000"+"00000000"+"4f495359534e4543"+"00000000"+
		"0100"+"0001"+"1400"+"0100"+"2001"+hex.EncodeToString([]byte("Communications"))+"0000")
	require.Equal(t, want, got)
}

func TestListInterfacesReply(t *testing.T) {
	req, _ := ParseHeader(censysListIdentity)
	req.Command = CmdListInterfaces
	got := ListInterfacesReply(req)
	require.Len(t, got, HeaderSize+2)
	h, _ := ParseHeader(got)
	require.Equal(t, uint16(2), h.Length)
	require.Equal(t, []byte{0, 0}, got[HeaderSize:])
}

func TestRegisterSessionReply(t *testing.T) {
	req := Header{Command: CmdRegisterSession, SenderContext: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}

	got, ok := RegisterSessionReply(req, []byte{1, 0, 0, 0}, 0xdeadbeef)
	require.True(t, ok)
	h, _ := ParseHeader(got)
	require.Equal(t, uint32(0xdeadbeef), h.SessionHandle)
	require.Equal(t, uint32(StatusSuccess), h.Status)
	require.Equal(t, req.SenderContext, h.SenderContext)
	require.Equal(t, []byte{1, 0, 0, 0}, got[HeaderSize:])

	got, ok = RegisterSessionReply(req, []byte{2, 0, 0, 0}, 0xdeadbeef)
	require.False(t, ok)
	h, _ = ParseHeader(got)
	require.Zero(t, h.SessionHandle)
	require.Equal(t, uint32(StatusUnsupportedRevision), h.Status)

	got, ok = RegisterSessionReply(req, []byte{1, 0}, 0xdeadbeef)
	require.False(t, ok)
	h, _ = ParseHeader(got)
	require.Equal(t, uint32(StatusInvalidLength), h.Status)
	require.Len(t, got, HeaderSize)
}

func TestNames(t *testing.T) {
	require.Equal(t, "ListIdentity", CommandName(CmdListIdentity))
	require.Equal(t, "0x1234", CommandName(0x1234))
	require.Equal(t, "invalid_command", StatusName(StatusInvalidCommand))
	require.Equal(t, "0x0099", StatusName(0x99))
}
