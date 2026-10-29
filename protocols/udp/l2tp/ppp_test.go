package l2tp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDataPlain(t *testing.T) {
	ppp := BuildPPP(true, ProtoLCP, CodeEchoRequest, 7, []byte{1, 2, 3, 4})
	msg := BuildData(0x1234, 0x5678, ppp)

	hdr, body, err := ParseData(msg)
	require.NoError(t, err)
	require.Equal(t, uint16(0x1234), hdr.TunnelID)
	require.Equal(t, uint16(0x5678), hdr.SessionID)
	require.Equal(t, ppp, body)
}

func TestParseDataLengthSequenceOffset(t *testing.T) {
	// L, S and O bits set, 2 offset pad bytes, trailing garbage past length
	msg := []byte{
		0x4a, 0x02, 0x00, 0x14, // flags, length 20
		0x00, 0x01, 0x00, 0x02, // tunnel, session
		0x00, 0x03, 0x00, 0x04, // ns, nr
		0x00, 0x02, 0xaa, 0xbb, // offset size 2 + pad
		0xc0, 0x21, 0x01, 0x01, // PPP (cut by length)
		0xff, 0xff,
	}
	hdr, body, err := ParseData(msg)
	require.NoError(t, err)
	require.Equal(t, DataHeader{TunnelID: 1, SessionID: 2, Ns: 3, Nr: 4}, hdr)
	require.Equal(t, []byte{0xc0, 0x21, 0x01, 0x01}, body)
}

func TestParseDataErrors(t *testing.T) {
	_, _, err := ParseData([]byte{0xc8, 0x02, 0, 12, 0, 1, 0, 0})
	require.Error(t, err, "control message")
	_, _, err = ParseData([]byte{0x00, 0x03, 0, 1, 0, 1})
	require.Error(t, err, "version 3")
	_, _, err = ParseData([]byte{0x40, 0x02, 0, 0x40, 0, 1, 0, 1})
	require.Error(t, err, "length past end")
	_, _, err = ParseData([]byte{0x02, 0x02, 0, 1, 0, 1, 0, 9})
	require.Error(t, err, "offset past end")
}

func TestParsePPP(t *testing.T) {
	p, err := ParsePPP([]byte{0xff, 0x03, 0xc0, 0x23, 0x01, 0x05, 0x00, 0x06, 0x00, 0x00, 0xee})
	require.NoError(t, err)
	require.True(t, p.ACF)
	require.Equal(t, uint16(ProtoPAP), p.Protocol)
	require.Equal(t, uint8(1), p.Code)
	require.Equal(t, uint8(5), p.ID)
	require.Equal(t, []byte{0x00, 0x00}, p.Data)

	// no ACF
	p, err = ParsePPP([]byte{0xc0, 0x21, 0x09, 0x01, 0x00, 0x08, 1, 2, 3, 4})
	require.NoError(t, err)
	require.False(t, p.ACF)
	require.Equal(t, "LCP Echo-Request", Command(p.Protocol, p.Code))

	_, err = ParsePPP([]byte{0xff, 0x03, 0x00, 0x21, 0x45})
	require.Error(t, err, "IPv4 is not a control protocol")
	_, err = ParsePPP([]byte{0xc0, 0x21, 0x01, 0x01, 0x00, 0x20})
	require.Error(t, err, "length past end")
}

func TestBuildPPPRoundTrip(t *testing.T) {
	data := ConfigureRequestOptions(ProtoCHAP, CHAPMSCHAPv2, 0xdeadbeef)
	p, err := ParsePPP(BuildPPP(true, ProtoLCP, CodeConfigureRequest, 3, data))
	require.NoError(t, err)
	require.Equal(t, data, p.Data)

	opts, err := ParseOptions(p.Data)
	require.NoError(t, err)
	proto, alg, ok := AuthOption(opts)
	require.True(t, ok)
	require.Equal(t, uint16(ProtoCHAP), proto)
	require.Equal(t, uint8(CHAPMSCHAPv2), alg)
	magic, ok := MagicNumber(opts)
	require.True(t, ok)
	require.Equal(t, uint32(0xdeadbeef), magic)
	require.Equal(t, "MS-CHAPv2", AuthName(proto, alg))
}

func TestParseOptionsInvalid(t *testing.T) {
	_, err := ParseOptions([]byte{0x01, 0x01})
	require.Error(t, err)
	_, err = ParseOptions([]byte{0x01, 0x09, 0x00})
	require.Error(t, err)
}

func TestParsePAPRequest(t *testing.T) {
	user, pass, err := ParsePAPRequest([]byte{5, 'a', 'd', 'm', 'i', 'n', 6, 'p', 'a', 's', 's', '1', '2'})
	require.NoError(t, err)
	require.Equal(t, "admin", user)
	require.Equal(t, "pass12", pass)

	user, _, err = ParsePAPRequest([]byte{2, 'v', 'p', 9, 'x'})
	require.Error(t, err)
	require.Equal(t, "vp", user)
	_, _, err = ParsePAPRequest([]byte{9})
	require.Error(t, err)
}

func TestCHAPChallengeAndResponse(t *testing.T) {
	ch := CHAPChallenge([]byte{1, 2, 3}, "lns")
	require.Equal(t, []byte{3, 1, 2, 3, 'l', 'n', 's'}, ch)

	value, name, err := ParseCHAPResponse([]byte{2, 0xab, 0xcd, 'b', 'o', 'b'})
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xcd}, value)
	require.Equal(t, "bob", name)
	_, _, err = ParseCHAPResponse([]byte{5, 1})
	require.Error(t, err)
}

func TestPAPMessage(t *testing.T) {
	require.Equal(t, []byte{4, 'f', 'a', 'i', 'l'}, PAPMessage("fail"))
}
