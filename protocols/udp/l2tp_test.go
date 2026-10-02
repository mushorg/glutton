package udp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func l2tpDraytekSCCRQ() []byte {
	// Captured scanner probe: Host Name=Vigor, Vendor Name=Draytek
	raw, err := base64.StdEncoding.DecodeString("yAIAWAAAAAAAAAABgAgAAAAAAAGACAAAAAIBAIALAAAAB1ZpZ29ygAoAAAADAAAAA4AIAAAACemZgAoAAAAEAAAAAwAIAAAABgABAA0AAAAIRHJheXRlaw==")
	if err != nil {
		panic(err)
	}
	return raw
}

func TestHandleL2TPSCCRQ(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 55193}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1701}
	payload := l2tpDraytekSCCRQ()

	err := HandleL2TP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "l2tp", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedL2TP)
	require.True(t, ok)
	require.Len(t, events, 2)

	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, uint16(1), events[0].MessageType)
	require.Equal(t, "SCCRQ", events[0].MessageName)
	require.Equal(t, "Vigor", events[0].HostName)
	require.Equal(t, "Draytek", events[0].VendorName)
	require.Equal(t, uint16(0xe999), events[0].AssignedTunnelID)
	require.Equal(t, payload, events[0].Payload)

	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, uint16(2), events[1].MessageType)
	require.Equal(t, "SCCRP", events[1].MessageName)
	require.Equal(t, l2tpHoneypotHostName, events[1].HostName)
	require.Equal(t, l2tpHoneypotVendorName, events[1].VendorName)
	require.Equal(t, uint16(0xe999), events[1].TunnelID)
	require.Equal(t, uint16(l2tpHoneypotTunnelID), events[1].AssignedTunnelID)
	require.Equal(t, h.replies[0], events[1].Payload)

	reply, err := parseL2TP(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, uint16(l2tpMsgSCCRP), reply.MessageType)
	require.Equal(t, "SCCRP", reply.MessageName)
	require.Equal(t, l2tpHoneypotHostName, reply.HostName)
	require.Equal(t, l2tpHoneypotVendorName, reply.VendorName)
	require.Equal(t, uint16(0xe999), reply.TunnelID)
	require.Equal(t, uint16(l2tpHoneypotTunnelID), reply.AssignedTunnelID)
	require.Equal(t, uint16(0), reply.Ns)
	require.Equal(t, uint16(1), reply.Nr)
}

func TestHandleL2TPNonSCCRQ(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1701}

	// Minimal HELLO: header + Message Type AVP only
	payload := []byte{
		0xc8, 0x02, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06,
		0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
	}

	err := HandleL2TP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedL2TP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "HELLO", events[0].MessageName)
	require.Equal(t, uint16(6), events[0].MessageType)
}

func TestHandleL2TPShortPacket(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1701}
	payload := []byte{0xc8, 0x02}

	err := HandleL2TP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "l2tp", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedL2TP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, payload, events[0].Payload)
	require.Empty(t, events[0].MessageName)
}

func TestHandleL2TPEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1701}

	err := HandleL2TP(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "l2tp", h.produced[0].handler)
	require.Empty(t, h.replies)
}

func TestBuildSCCRPRoundTrip(t *testing.T) {
	resp := buildSCCRP(0xe999, 0)
	require.GreaterOrEqual(t, len(resp), 12)
	require.Equal(t, uint16(len(resp)), binary.BigEndian.Uint16(resp[2:4]))

	frame, err := parseL2TP(resp)
	require.NoError(t, err)
	require.Equal(t, "SCCRP", frame.MessageName)
	require.Equal(t, uint16(0xe999), frame.TunnelID)
	require.Equal(t, uint16(l2tpHoneypotTunnelID), frame.AssignedTunnelID)
	require.Equal(t, l2tpHoneypotHostName, frame.HostName)
	require.Equal(t, l2tpHoneypotVendorName, frame.VendorName)
}

func TestParseL2TPDataMessage(t *testing.T) {
	// T-bit clear → data message
	_, err := parseL2TP([]byte{0x40, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01})
	require.Error(t, err)
}
