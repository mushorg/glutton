package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func coapGETWellKnown() []byte {
	return encodeCoAP(coapTypeCON, coapCodeGET, 0x0001, nil, []coapOption{
		{num: coapOptURIPath, value: []byte(".well-known")},
		{num: coapOptURIPath, value: []byte("core")},
	}, nil)
}

func coapGETTemp() []byte {
	return encodeCoAP(coapTypeCON, coapCodeGET, 0x0002, []byte{0xaa, 0xbb}, []coapOption{
		{num: coapOptURIPath, value: []byte("ps")},
		{num: coapOptURIPath, value: []byte("temp")},
	}, nil)
}

func coapPOST() []byte {
	return encodeCoAP(coapTypeCON, coapCodePOST, 0x0003, nil, []coapOption{
		{num: coapOptURIPath, value: []byte("ps")},
		{num: coapOptURIPath, value: []byte("temp")},
	}, []byte("22"))
}

func TestHandleCoAPWellKnownGET(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 34567}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5683}
	payload := coapGETWellKnown()

	err := HandleCoAP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "coap", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedCoAP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "CON", events[0].Type)
	require.Equal(t, "GET", events[0].CodeName)
	require.Equal(t, "GET", events[0].Command)
	require.Equal(t, coapWellKnownCore, events[0].Path)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "ACK", events[1].Type)
	require.Equal(t, "CONTENT", events[1].CodeName)
	require.Equal(t, "CONTENT", events[1].Command)
	require.Equal(t, "CONTENT", events[1].Status)
	require.Equal(t, h.replies[0], events[1].Payload)

	_, reply, err := parseCoAP(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, uint8(coapTypeACK), reply.Type)
	require.Equal(t, uint8(coapCodeContent), reply.Code)
	require.Equal(t, []byte(coapLinkBody), reply.Body)
}

func TestHandleCoAPPOSTCreated(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 34567}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5683}

	err := HandleCoAP(context.Background(), src, dst, coapPOST(), connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedCoAP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "POST", events[0].CodeName)
	require.Equal(t, "ps/temp", events[0].Path)
	require.Equal(t, "CREATED", events[1].CodeName)

	_, reply, err := parseCoAP(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, uint8(coapCodeCreated), reply.Code)
}

func TestHandleCoAPGETToken(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5683}

	err := HandleCoAP(context.Background(), src, dst, coapGETTemp(), connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedCoAP)
	require.True(t, ok)
	require.Equal(t, "aabb", events[0].Token)
	require.Equal(t, "CONTENT", events[1].CodeName)

	_, reply, err := parseCoAP(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa, 0xbb}, reply.Token)
	require.Equal(t, []byte(coapGETBody), reply.Body)
}

func TestHandleCoAPShortAndGarbageStillProduce(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5683}

	for _, payload := range [][]byte{nil, {0x40, 0x01}, {0x00, 0x01, 0x00, 0x01}} {
		h := &recordingHoneypot{}
		err := HandleCoAP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
		require.NoError(t, err)
		require.Len(t, h.produced, 1)
		require.Equal(t, "coap", h.produced[0].handler)
		require.Empty(t, h.replies)
		events, ok := h.produced[0].decoded.([]parsedCoAP)
		require.True(t, ok)
		require.Len(t, events, 1)
		require.Equal(t, "UNKNOWN", events[0].CodeName)
	}
}

func TestLooksLikeCoAP(t *testing.T) {
	require.True(t, looksLikeCoAP(coapGETWellKnown()))
	require.True(t, looksLikeCoAP(coapPOST()))
	require.False(t, looksLikeCoAP(nil))
	require.False(t, looksLikeCoAP([]byte{0x40, 0x01}))
	require.False(t, looksLikeCoAP([]byte{0x00, 0x01, 0x00, 0x01}))
	require.False(t, looksLikeCoAP([]byte{0x40, 0x00, 0x00, 0x01})) // empty CON ping
}

func TestHandleUDPPeeksCoAP(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 34567}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 12345}
	payload := coapGETWellKnown()

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "coap", h.produced[0].handler)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedCoAP)
	require.True(t, ok)
	require.Equal(t, "GET", events[0].CodeName)
}
