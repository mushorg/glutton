package udp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func kerberosASReqFromEvent() []byte {
	// Ochi event 9f61359e-9c4d-442f-88e6-70b674eace8d: UDP AS-REQ for krbtgt/NM.
	raw, err := hex.DecodeString("6a816e30816ba103020105a20302010aa4815e305ca00703050050800010a2041b024e4da3173015a003020100a10e300c1b066b72627467741b024e4da511180f31393730303130313030303030305aa70602041f1eb9d9a8173015020112020111020110020117020101020103020102")
	if err != nil {
		panic(err)
	}
	return raw
}

func TestHandleKerberosASReq(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := kerberosASReqFromEvent()

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, 10, events[0].MsgType)
	require.Equal(t, "AS-REQ", events[0].MsgName)
	require.Equal(t, 5, events[0].PVNO)
	require.Equal(t, "NM", events[0].Realm)
	require.Equal(t, "krbtgt/NM", events[0].SName)
	require.Empty(t, events[0].CName)
	require.Equal(t, []int{18, 17, 16, 23, 1, 3, 2}, events[0].ETypes)
	require.Equal(t, 0x1f1eb9d9, events[0].Nonce)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleKerberosTruncated(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := []byte{0x6a, 0x81, 0x6e, 0x30}

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "UNKNOWN", events[0].MsgName)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleKerberosNonDER(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := []byte{0x00, 0x01, 0x02, 0x03}

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "UNKNOWN", events[0].MsgName)
	require.Zero(t, events[0].MsgType)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleUDPPeeksKerberos(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8000}
	payload := kerberosASReqFromEvent()

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Equal(t, "AS-REQ", events[0].MsgName)
	require.Equal(t, "NM", events[0].Realm)
	require.Equal(t, "krbtgt/NM", events[0].SName)
}

func TestParseKerberosTGSReqName(t *testing.T) {
	payload := kerberosASReqFromEvent()
	payload[0] = 0x6c // APPLICATION 12
	frame := parseKerberos(payload)
	require.Equal(t, 12, frame.MsgType)
	require.Equal(t, "TGS-REQ", frame.MsgName)
	require.Equal(t, "NM", frame.Realm)
	require.Equal(t, "krbtgt/NM", frame.SName)
}

func TestLooksLikeKerberos(t *testing.T) {
	require.True(t, looksLikeKerberos(kerberosASReqFromEvent()))
	require.False(t, looksLikeKerberos(nil))
	require.False(t, looksLikeKerberos([]byte{0x00, 0x01}))
	require.False(t, looksLikeKerberos([]byte{0x6a, 0x03, 0xff, 0x00, 0x00}))
}
