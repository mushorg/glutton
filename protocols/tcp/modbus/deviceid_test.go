package modbus

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseReadDeviceID(t *testing.T) {
	req, ok := ParseReadDeviceID([]byte{0x2b, 0x0e, 0x01, 0x00})
	require.True(t, ok)
	require.Equal(t, ReadDeviceIDRequest{Code: 1, ObjectID: 0}, req)

	for _, pdu := range [][]byte{nil, {0x2b, 0x0e, 0x01}, {0x2b, 0x0d, 0x01, 0x00}, {0x03, 0x0e, 0x01, 0x00}} {
		_, ok := ParseReadDeviceID(pdu)
		require.False(t, ok, "%x", pdu)
	}
}

func objectIDs(t *testing.T, pdu []byte) []byte {
	t.Helper()
	var ids []byte
	rest := pdu[7:]
	for i := 0; i < int(pdu[6]); i++ {
		require.GreaterOrEqual(t, len(rest), 2)
		ids = append(ids, rest[0])
		rest = rest[2+int(rest[1]):]
	}
	require.Empty(t, rest)
	return ids
}

func TestReadDeviceIDReply(t *testing.T) {
	id := DefaultDeviceIdentity
	cases := []struct {
		req  ReadDeviceIDRequest
		want []byte
	}{
		{ReadDeviceIDRequest{Code: ReadDeviceIDBasic}, []byte{0, 1, 2}},
		{ReadDeviceIDRequest{Code: ReadDeviceIDBasic, ObjectID: 1}, []byte{1, 2}},
		{ReadDeviceIDRequest{Code: ReadDeviceIDBasic, ObjectID: 5}, []byte{0, 1, 2}},
		{ReadDeviceIDRequest{Code: ReadDeviceIDRegular}, []byte{0, 1, 2, 3, 4, 5, 6}},
		{ReadDeviceIDRequest{Code: ReadDeviceIDExtended, ObjectID: 0x80}, []byte{0, 1, 2, 3, 4, 5, 6}},
		{ReadDeviceIDRequest{Code: ReadDeviceIDIndividual, ObjectID: 4}, []byte{4}},
	}
	for _, c := range cases {
		pdu, exc := ReadDeviceIDReply(c.req, id)
		require.Zero(t, exc)
		require.Equal(t, []byte{0x2b, 0x0e, c.req.Code, 0x82, 0x00, 0x00}, pdu[:6])
		require.Equal(t, c.want, objectIDs(t, pdu), "%+v", c.req)
	}

	_, exc := ReadDeviceIDReply(ReadDeviceIDRequest{Code: ReadDeviceIDIndividual, ObjectID: 7}, id)
	require.Equal(t, ExcIllegalDataAddress, exc)
	_, exc = ReadDeviceIDReply(ReadDeviceIDRequest{Code: 0x05}, id)
	require.Equal(t, ExcIllegalDataValue, exc)
}

func TestReadDeviceIDReplyMoreFollows(t *testing.T) {
	long := strings.Repeat("a", 200)
	id := DeviceIdentity{VendorName: long, ProductCode: long, MajorMinorRevision: "1"}
	pdu, exc := ReadDeviceIDReply(ReadDeviceIDRequest{Code: ReadDeviceIDBasic}, id)
	require.Zero(t, exc)
	require.LessOrEqual(t, len(pdu), 253)
	require.Equal(t, byte(0xFF), pdu[4])
	require.Equal(t, byte(1), pdu[5])
	require.Equal(t, []byte{0}, objectIDs(t, pdu))
}
