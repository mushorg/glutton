package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/bacnet"
	"github.com/stretchr/testify/require"
)

// Captured Shadowserver probe (run-1794142122-2.jsonl event #7, udp/47808):
// ReadProperty device:4194303 object-identifier.
var bacnetCapturedReadProperty = []byte{0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x63, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b}

func bacnetAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("199.165.159.110"), Port: 53217},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 47808}
}

func TestHandleBACnetCapturedReadProperty(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := bacnetAddrs()
	require.NoError(t, HandleBACnet(context.Background(), src, dst, bacnetCapturedReadProperty, connection.Metadata{}, testLogger{}, h))

	require.Len(t, h.produced, 1)
	require.Equal(t, "bacnet", h.produced[0].handler)
	require.Equal(t, bacnetCapturedReadProperty, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	m, err := bacnet.Parse(bacnetCapturedReadProperty)
	require.NoError(t, err)
	want := bacnet.Respond(m, bacnet.DeviceFor([]byte("198.51.100.1"))).Payload
	require.Equal(t, [][]byte{want}, h.replies)
	invoke := 0x63
	require.Equal(t, []parsedBACnet{
		{Direction: "read", Command: "READ_PROPERTY", BVLCFunction: "ORIGINAL_UNICAST_NPDU", InvokeID: &invoke, Path: "device:4194303", Property: "object-identifier", Payload: bacnetCapturedReadProperty},
		{Direction: "write", Command: "READ_PROPERTY", InvokeID: &invoke, Path: "device:4194303", Property: "object-identifier", Status: "READ_PROPERTY_ACK", Payload: want},
	}, h.produced[0].decoded)
}

func TestHandleBACnetMalformed(t *testing.T) {
	src, dst := bacnetAddrs()
	for name, b := range map[string][]byte{
		"short":           {0x81, 0x0a},
		"bad bvlc type":   {0x82, 0x0a, 0x00, 0x04},
		"length mismatch": bacnetCapturedReadProperty[:10],
	} {
		t.Run(name, func(t *testing.T) {
			h := &recordingHoneypot{}
			require.NoError(t, HandleBACnet(context.Background(), src, dst, b, connection.Metadata{}, testLogger{}, h))
			require.Len(t, h.produced, 1)
			require.Empty(t, h.replies)
			ev := h.produced[0].decoded.([]parsedBACnet)
			require.Len(t, ev, 1)
			require.Equal(t, "read", ev[0].Direction)
			require.Equal(t, b, ev[0].Payload)
		})
	}
}

func TestHandleBACnetOversize(t *testing.T) {
	src, dst := bacnetAddrs()
	big := make([]byte, maxBACnetPayload+100)
	copy(big, bacnetCapturedReadProperty)
	h := &recordingHoneypot{}
	require.NoError(t, HandleBACnet(context.Background(), src, dst, big, connection.Metadata{}, testLogger{}, h))
	ev := h.produced[0].decoded.([]parsedBACnet)
	require.Len(t, ev, 1)
	require.True(t, ev[0].Truncated)
	require.Len(t, ev[0].Payload, maxBACnetPayload)
	require.Empty(t, h.replies)
}

func TestHandleUDPReroutesBACnet(t *testing.T) {
	src, _ := bacnetAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 47809}
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, bacnetCapturedReadProperty, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "bacnet", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}
