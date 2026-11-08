package bacnet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured Shadowserver probe (run-1794142122-2.jsonl event #7): ReadProperty
// device:4194303 object-identifier, invoke ID 0x63.
var capturedReadProperty = []byte{0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x63, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b}

var testDevice = Device{Instance: 1234, Name: "AHU-1", VendorID: 8, VendorName: "Delta Controls", Model: "eBCON", Firmware: "V3.40"}

func TestParseCapturedReadProperty(t *testing.T) {
	require.True(t, LooksLikeBACnet(capturedReadProperty))
	m, err := Parse(capturedReadProperty)
	require.NoError(t, err)
	require.Equal(t, "READ_PROPERTY", m.Command())
	require.Equal(t, "ORIGINAL_UNICAST_NPDU", m.FunctionName())
	require.True(t, m.ExpectReply)
	require.Equal(t, byte(0x63), m.InvokeID)
	require.Equal(t, "device:4194303", m.Object.String())
	require.Equal(t, uint32(75), *m.Property)
	require.Nil(t, m.ArrayIndex)
}

func TestRespondReadPropertyACK(t *testing.T) {
	m, err := Parse(capturedReadProperty)
	require.NoError(t, err)
	r := Respond(m, testDevice)
	require.Equal(t, "READ_PROPERTY_ACK", r.Status)
	require.Equal(t, []byte{
		0x81, 0x0a, 0x00, 0x17, 0x01, 0x00,
		0x30, 0x63, 0x0c, 0x0c, 0x02, 0x00, 0x04, 0xd2, 0x19, 0x4b,
		0x3e, 0xc4, 0x02, 0x00, 0x04, 0xd2, 0x3f,
	}, r.Payload)

	// vendor-name (121) is a character string
	vn := append([]byte(nil), capturedReadProperty...)
	vn[16] = 121
	m, err = Parse(vn)
	require.NoError(t, err)
	r = Respond(m, testDevice)
	require.Equal(t, "READ_PROPERTY_ACK", r.Status)
	require.Contains(t, string(r.Payload), "\x3e\x75\x0f\x00Delta Controls\x3f")
}

func TestRespondErrors(t *testing.T) {
	cases := map[string]struct {
		mutate func([]byte) []byte
		status string
	}{
		"unknown property": {func(b []byte) []byte { b[16] = 85; return b }, "ERROR:property/unknown-property"},
		"other device":     {func(b []byte) []byte { b[14] = 0x01; return b }, "ERROR:object/unknown-object"},
		"analog input":     {func(b []byte) []byte { b[11] = 0x00; return b }, "ERROR:object/unknown-object"},
		"array index": {func(b []byte) []byte {
			b = append(b, 0x29, 0x01)
			b[3] = byte(len(b))
			return b
		}, "ERROR:property/property-is-not-an-array"},
		"read property multiple": {func(b []byte) []byte { b[9] = 0x0e; return b }, "REJECT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b := tc.mutate(append([]byte(nil), capturedReadProperty...))
			m, err := Parse(b)
			require.NoError(t, err)
			r := Respond(m, testDevice)
			require.NotNil(t, r)
			require.Equal(t, tc.status, r.Status)
		})
	}
	m, _ := Parse(capturedReadProperty)
	require.Equal(t, []byte{0x81, 0x0a, 0x00, 0x0d, 0x01, 0x00, 0x50, 0x63, 0x0c, 0x91, 0x02, 0x91, 0x20},
		BuildError(m, ErrClassProperty, ErrCodeUnknownProperty))
}

func TestWhoIsIAm(t *testing.T) {
	// Global Who-Is (broadcast)
	whoIs := []byte{0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08}
	whoIs[3] = byte(len(whoIs))
	require.True(t, LooksLikeBACnet(whoIs))
	m, err := Parse(whoIs)
	require.NoError(t, err)
	require.Equal(t, "WHO_IS", m.Command())
	r := Respond(m, testDevice)
	require.Equal(t, "I_AM", r.Status)
	require.Equal(t, []byte{0x81, 0x0a, 0x00, 0x14, 0x01, 0x00,
		0x10, 0x00, 0xc4, 0x02, 0x00, 0x04, 0xd2, 0x22, 0x05, 0xc4, 0x91, 0x03, 0x21, 0x08}, r.Payload)

	// Ranged Who-Is that excludes the device stays silent.
	ranged := []byte{0x81, 0x0a, 0x00, 0x0e, 0x01, 0x00, 0x10, 0x08, 0x09, 0x01, 0x19, 0x0a}
	ranged[3] = byte(len(ranged))
	m, err = Parse(ranged)
	require.NoError(t, err)
	require.Equal(t, uint32(1), *m.LowLimit)
	require.Equal(t, uint32(10), *m.HighLimit)
	require.Nil(t, Respond(m, testDevice))
}

func TestRoutedRequestReplyIsRouted(t *testing.T) {
	// NPDU with SNET 5 / SADR 0x07.
	b := []byte{0x81, 0x0a, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x05, 0x01, 0x07, 0x10, 0x08}
	b[3] = byte(len(b))
	m, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, &Address{Net: 5, MAC: []byte{7}}, m.Source)
	r := Respond(m, testDevice)
	require.Equal(t, []byte{0x01, 0x20, 0x00, 0x05, 0x01, 0x07, 0xff, 0x10, 0x00}, r.Payload[4:13])
}

func TestDeviceControlPassword(t *testing.T) {
	// ReinitializeDevice warmstart, password "admin"
	b := []byte{0x81, 0x0a, 0x00, 0x00, 0x01, 0x04, 0x00, 0x05, 0x01, 0x14, 0x09, 0x01, 0x1d, 0x06, 0x00, 'a', 'd', 'm', 'i', 'n'}
	b[3] = byte(len(b))
	m, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, "REINITIALIZE_DEVICE", m.Command())
	require.Equal(t, "admin", m.Password)
	require.Equal(t, "ERROR:security/password-failure", Respond(m, testDevice).Status)
}

func TestBVLLOnly(t *testing.T) {
	m, err := Parse([]byte{0x81, 0x02, 0x00, 0x04})
	require.NoError(t, err)
	require.Equal(t, "READ_BDT", m.Command())
	r := Respond(m, testDevice)
	require.Equal(t, []byte{0x81, 0x00, 0x00, 0x06, 0x00, 0x20}, r.Payload)
}

func TestParseMalformed(t *testing.T) {
	_, err := Parse([]byte{0x81, 0x0a})
	require.ErrorIs(t, err, ErrShort)
	_, err = Parse([]byte{0x82, 0x0a, 0x00, 0x04})
	require.ErrorIs(t, err, ErrMagic)
	m, err := Parse(capturedReadProperty[:12])
	require.ErrorIs(t, err, ErrLength)
	require.NotNil(t, m)
	short := append([]byte(nil), capturedReadProperty[:12]...)
	short[3] = 12
	_, err = Parse(short)
	require.ErrorIs(t, err, ErrAPDU)
}

func TestLooksLikeBACnetNegative(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0x81, 0x0a, 0x00, 0x05, 0x02},    // wrong NPDU version
		{0x81, 0x0a, 0x00, 0x20, 0x01, 0}, // length mismatch
		{0x81, 0x7f, 0x00, 0x04},          // unknown function
		{0x06, 0x10, 0x02, 0x03, 0x00, 6}, // KNX
		[]byte("GET / HTTP/1.1\r\n\r\n"),
	} {
		require.False(t, LooksLikeBACnet(b), "%x", b)
	}
}

func TestDeviceForStable(t *testing.T) {
	a, b := DeviceFor([]byte("198.51.100.1")), DeviceFor([]byte("198.51.100.1"))
	require.Equal(t, a, b)
	require.GreaterOrEqual(t, a.Instance, uint32(1000))
	require.Less(t, a.Instance, WildcardInstance)
}
