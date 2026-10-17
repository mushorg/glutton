package slp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured infrawatch SrvRqst (Ochi event 79c746cf-1e02-4e46-baf8-b4c69438d318).
var capturedSrvRqst = []byte{
	0x02, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 0x65, 0x6e,
	0x00, 0x00, 0x00, 0x2a, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x69, 0x77, 0x73, 0x63,
	0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37, 0x35, 0x63, 0x31, 0x65,
	0x35, 0x31, 0x64, 0x2e, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x77, 0x61, 0x74, 0x63, 0x68, 0x00, 0x17,
	0x69, 0x77, 0x73, 0x63, 0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37,
	0x35, 0x63, 0x31, 0x65, 0x35, 0x31, 0x64, 0x00, 0x00, 0x00, 0x00,
}

func TestParseCapturedSrvRqst(t *testing.T) {
	h, err := ParseHeader(capturedSrvRqst)
	require.NoError(t, err)
	require.Equal(t, uint8(FuncSrvRqst), h.Function)
	require.Equal(t, uint16(0xc0e8), h.XID)
	require.Equal(t, "en", h.Lang)
	require.Equal(t, uint32(91), h.Length)

	q, err := ParseRequest(capturedSrvRqst, h)
	require.NoError(t, err)
	require.Equal(t, Request{ServiceType: "service:iwscan-c60d855275c1e51d.infrawatch", Scope: "iwscan-c60d855275c1e51d"}, q)
}

func TestReplyScopeNotSupported(t *testing.T) {
	h, err := ParseHeader(capturedSrvRqst)
	require.NoError(t, err)
	q, err := ParseRequest(capturedSrvRqst, h)
	require.NoError(t, err)

	reply, code := Reply(h, q)
	require.Equal(t, uint16(ErrScopeNotSupported), code)
	// v2 SrvRply, length 20, xid c0e8, lang "en", error 4, 0 URLs
	require.Equal(t, []byte{
		0x02, 0x02, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 'e', 'n',
		0x00, 0x04, 0x00, 0x00,
	}, reply)
	require.Less(t, len(reply), len(capturedSrvRqst))
}

func TestReplyDefaultScope(t *testing.T) {
	h := Header{Function: FuncSrvRqst, XID: 1, Lang: "en"}
	reply, code := Reply(h, Request{Scope: "foo, Default"})
	require.Zero(t, code)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, reply[len(reply)-4:])
}

func TestReplyOtherFunctions(t *testing.T) {
	typeReply, _ := Reply(Header{Function: FuncSrvTypeRqst, XID: 2, Lang: "en"}, Request{Scope: "default"})
	require.Equal(t, uint8(FuncSrvTypeRply), typeReply[1])
	require.Equal(t, 20, len(typeReply))

	attrReply, _ := Reply(Header{Function: FuncAttrRqst, XID: 3, Lang: "en"}, Request{Scope: "x"})
	require.Equal(t, uint8(FuncAttrRply), attrReply[1])
	require.Equal(t, 21, len(attrReply))
	require.Equal(t, byte(0x04), attrReply[17]) // error code low byte

	none, _ := Reply(Header{Function: FuncSrvReg}, Request{})
	require.Nil(t, none)
}

func TestReplyMulticastSilent(t *testing.T) {
	reply, _ := Reply(Header{Function: FuncSrvRqst, Flags: FlagMulticast}, Request{Scope: "default"})
	require.Nil(t, reply)
}

func TestParseHeaderErrors(t *testing.T) {
	_, err := ParseHeader(capturedSrvRqst[:10])
	require.ErrorIs(t, err, ErrShort)

	v1 := append([]byte(nil), capturedSrvRqst...)
	v1[0] = 1
	_, err = ParseHeader(v1)
	require.ErrorIs(t, err, ErrVersion)

	_, err = ParseHeader(capturedSrvRqst[:60])
	require.ErrorIs(t, err, ErrLength)

	badLang := append([]byte(nil), capturedSrvRqst[:14]...)
	badLang[4] = 14
	badLang[13] = 9 // language tag longer than the datagram
	_, err = ParseHeader(badLang)
	require.ErrorIs(t, err, ErrBody)
}

func TestParseRequestBadLengths(t *testing.T) {
	// service type length points past the end of the datagram
	b := append([]byte(nil), capturedSrvRqst...)
	b[19] = 0xff
	h, err := ParseHeader(b)
	require.NoError(t, err)
	_, err = ParseRequest(b, h)
	require.ErrorIs(t, err, ErrBody)

	// body ends right after the previous-responder list
	short := append([]byte(nil), capturedSrvRqst[:18]...)
	short[4] = 18
	h, err = ParseHeader(short)
	require.NoError(t, err)
	_, err = ParseRequest(short, h)
	require.ErrorIs(t, err, ErrBody)
}

func TestNames(t *testing.T) {
	require.Equal(t, "SrvRqst", FunctionName(1))
	require.Equal(t, "function_99", FunctionName(99))
	require.Equal(t, "SCOPE_NOT_SUPPORTED", ErrorName(4))
	require.Equal(t, "error_99", ErrorName(99))
}
