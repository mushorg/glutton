package bgp

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanOpen is the 29-byte OPEN captured from Shodan on tcp/179
// (run-1793745705 events #50/#51): AS 19384, hold time 180, no options.
var shodanOpen = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x1d, 0x01, 0x04, 0x4b, 0xb8, 0x00, 0xb4,
	0xd8, 0x75, 0x02, 0xb4, 0x00,
}

func marker() []byte { return bytes.Repeat([]byte{0xff}, 16) }

func TestReadMessageShodanOpen(t *testing.T) {
	h, raw, err := ReadMessage(bytes.NewReader(shodanOpen))
	require.NoError(t, err)
	require.Equal(t, Header{Length: 29, Type: TypeOpen}, h)
	require.Equal(t, shodanOpen, raw)

	o, err := ParseOpen(raw[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, Open{Version: 4, AS: 19384, HoldTime: 180, BGPID: "216.117.2.180"}, o)
}

func TestReadMessageShortHeader(t *testing.T) {
	_, raw, err := ReadMessage(bytes.NewReader(shodanOpen[:10]))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, shodanOpen[:10], raw)
}

func TestReadMessageShortBody(t *testing.T) {
	h, raw, err := ReadMessage(bytes.NewReader(shodanOpen[:25]))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, TypeOpen, h.Type)
	require.Equal(t, shodanOpen[:25], raw)
}

func TestParseHeaderErrors(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		subcode uint8
		data    []byte
	}{
		{"marker", append([]byte("GET / HTTP/1.1\r\n\r\n"), 0), SubConnectionNotSynchronized, nil},
		{"too long", append(marker(), 0x10, 0x01, TypeUpdate), SubBadMessageLength, []byte{0x10, 0x01}},
		{"too short", append(marker(), 0x00, 0x12, TypeKeepalive), SubBadMessageLength, []byte{0x00, 0x12}},
		{"keepalive with body", append(marker(), 0x00, 0x14, TypeKeepalive), SubBadMessageLength, []byte{0x00, 0x14}},
		{"short open", append(marker(), 0x00, 0x1c, TypeOpen), SubBadMessageLength, []byte{0x00, 0x1c}},
		{"unknown type", append(marker(), 0x00, 0x13, 9), SubBadMessageType, []byte{9}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHeader(tc.in)
			var he *HeaderError
			require.True(t, errors.As(err, &he), "got %v", err)
			require.Equal(t, tc.subcode, he.Subcode)
			require.Equal(t, tc.data, he.Data)
		})
	}
}

func TestBuildOpenRoundTrip(t *testing.T) {
	msg := BuildOpen(65001, 180, [4]byte{10, 0, 0, 1})
	h, err := ParseHeader(msg)
	require.NoError(t, err)
	require.Equal(t, TypeOpen, h.Type)
	require.Equal(t, int(h.Length), len(msg))

	o, err := ParseOpen(msg[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, uint8(4), o.Version)
	require.Equal(t, uint16(65001), o.AS)
	require.Equal(t, uint16(180), o.HoldTime)
	require.Equal(t, "10.0.0.1", o.BGPID)
	require.Equal(t, []uint8{CapMultiprotocol, CapRouteRefresh, CapFourOctetAS}, o.Capabilities)
	require.Equal(t, uint32(65001), o.AS4)
}

func TestParseOpenOptParamsOverrun(t *testing.T) {
	body := append([]byte(nil), shodanOpen[HeaderLen:]...)
	body[9] = 8
	_, err := ParseOpen(body)
	require.ErrorIs(t, err, ErrShortOpen)
}

func TestBuildKeepaliveAndNotification(t *testing.T) {
	require.Equal(t, append(marker(), 0x00, 0x13, TypeKeepalive), BuildKeepalive())

	n := BuildNotification(ErrCodeOpen, SubUnsupportedVersion, []byte{0, 4})
	require.Equal(t, append(marker(), 0x00, 0x17, TypeNotification, 2, 1, 0, 4), n)
	h, err := ParseHeader(n)
	require.NoError(t, err)
	parsed, ok := ParseNotification(n[HeaderLen:h.Length])
	require.True(t, ok)
	require.Equal(t, Notification{Code: 2, Subcode: 1, Data: []byte{0, 4}}, parsed)
}

func TestTypeName(t *testing.T) {
	require.Equal(t, "OPEN", TypeName(TypeOpen))
	require.Equal(t, "ROUTE-REFRESH", TypeName(TypeRouteRefresh))
	require.Equal(t, "type-9", TypeName(9))
}
