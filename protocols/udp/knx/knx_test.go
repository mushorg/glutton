package knx

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured DESCRIPTION_REQUEST (Ochi event 25167000-a41c-4107-ac35-342898a51e57).
var capturedDescription = []byte{0x06, 0x10, 0x02, 0x03, 0x00, 0x0e, 0x08, 0x01, 0xcf, 0x5a, 0xf4, 0x03, 0x0e, 0x58}

func TestParseDescriptionRequest(t *testing.T) {
	req, err := Parse(capturedDescription)
	require.NoError(t, err)
	require.Equal(t, DescriptionRequest, req.ServiceType)
	require.Equal(t, "DESCRIPTION_REQUEST", req.Command())
	require.Equal(t, byte(HPAIUDP), req.HPAI.Protocol)
	require.Equal(t, "207.90.244.3", req.HPAI.IP.String())
	require.Equal(t, uint16(3672), req.HPAI.Port)
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(capturedDescription[:4])
	require.ErrorIs(t, err, ErrShort)

	_, err = Parse([]byte{0x07, 0x10, 0x02, 0x03, 0x00, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0})
	require.ErrorIs(t, err, ErrMagic)

	bad := append([]byte(nil), capturedDescription...)
	bad[5] = 0x10
	req, err := Parse(bad)
	require.ErrorIs(t, err, ErrLength)
	require.Equal(t, DescriptionRequest, req.ServiceType)
	require.Equal(t, "DESCRIPTION_REQUEST", req.Command()) // callers must not trust it on error

	badHPAI := append([]byte(nil), capturedDescription...)
	badHPAI[6] = 0x07
	_, err = Parse(badHPAI)
	require.ErrorIs(t, err, ErrBadHPAI)
}

func TestParseOtherServices(t *testing.T) {
	// CONNECTIONSTATE_REQUEST: channel, reserved, HPAI.
	cs := []byte{6, 0x10, 0x02, 0x07, 0, 16, 0x15, 0, 8, 2, 10, 0, 0, 1, 0x0e, 0x57}
	req, err := Parse(cs)
	require.NoError(t, err)
	require.Equal(t, "CONNECTIONSTATE_REQUEST", req.Command())
	require.Equal(t, "10.0.0.1", req.HPAI.IP.String())
	require.Equal(t, byte(HPAITCP), req.HPAI.Protocol)

	unk, err := Parse([]byte{6, 0x10, 0x04, 0x20, 0, 6})
	require.NoError(t, err)
	require.Equal(t, "UNKNOWN", unk.Command())
	require.Nil(t, unk.HPAI)
}

func TestLooksLikeKNX(t *testing.T) {
	require.True(t, LooksLikeKNX(capturedDescription))
	require.False(t, LooksLikeKNX(capturedDescription[:13]))
	require.False(t, LooksLikeKNX(nil))
	// Unknown service type and a response type are not rerouted.
	require.False(t, LooksLikeKNX([]byte{6, 0x10, 0x04, 0x20, 0, 6}))
	require.False(t, LooksLikeKNX([]byte{6, 0x10, 0x02, 0x04, 0, 6}))
	// Wrong header size or protocol version.
	require.False(t, LooksLikeKNX([]byte{5, 0x10, 0x02, 0x03, 0, 6}))
	require.False(t, LooksLikeKNX([]byte{6, 0x20, 0x02, 0x03, 0, 6}))
	require.False(t, LooksLikeKNX([]byte("GET / HTTP/1.1\r\n")))
}

func TestBuildDescriptionResponse(t *testing.T) {
	d := DeviceFor([]byte("198.51.100.1"))
	require.Equal(t, d, DeviceFor([]byte("198.51.100.1")))
	require.NotEqual(t, d, DeviceFor([]byte("198.51.100.2")))

	b := BuildDescriptionResponse(d)
	require.Len(t, b, 68)
	require.Equal(t, []byte{6, 0x10, 0x02, 0x04, 0x00, 68}, b[:6])
	require.Equal(t, []byte{54, 0x01, 0x02, 0x00, 0x11, 0x01}, b[6:12])
	require.Equal(t, d.Serial[:], b[6+8:6+14])
	require.Equal(t, d.MAC[:], b[6+18:6+24])
	require.Equal(t, "IP Interface", string(b[6+24:6+36]))
	require.Equal(t, []byte{8, 0x02, 2, 1, 3, 1, 4, 1}, b[60:])
}

func TestBuildSearchResponse(t *testing.T) {
	d := DeviceFor([]byte("x"))
	b := BuildSearchResponse(d, net.ParseIP("198.51.100.1"), 3671)
	require.Len(t, b, 76)
	require.Equal(t, []byte{6, 0x10, 0x02, 0x02, 0x00, 76}, b[:6])
	require.Equal(t, []byte{8, 0x01, 198, 51, 100, 1, 0x0e, 0x57}, b[6:14])
	require.Equal(t, BuildDescriptionResponse(d)[6:], b[14:])

	v6 := BuildSearchResponse(d, net.ParseIP("2001:db8::1"), 3671)
	require.Equal(t, []byte{8, 0x01, 0, 0, 0, 0, 0x0e, 0x57}, v6[6:14])
}

func TestBuildConnectError(t *testing.T) {
	require.Equal(t, []byte{6, 0x10, 0x02, 0x06, 0, 8, 0, 0x24}, BuildConnectError())
}
