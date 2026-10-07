package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func openVPNHardResetInternet() []byte {
	// opcode 7 (P_CONTROL_HARD_RESET_CLIENT_V2), key_id 0, session ID "internet"
	return []byte{0x38, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't', 0, 0, 0, 0, 0}
}

func TestHandleOpenVPNHardReset(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 61611}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := openVPNHardResetInternet()

	err := HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedOpenVPN)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, uint8(7), events[0].Opcode)
	require.Equal(t, "P_CONTROL_HARD_RESET_CLIENT_V2", events[0].OpcodeName)
	require.Equal(t, "P_CONTROL_HARD_RESET_CLIENT_V2", events[0].Command)
	require.Equal(t, uint8(0), events[0].KeyID)
	require.Equal(t, "696e7465726e6574", events[0].SessionID)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleOpenVPNShortPacket(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := []byte{0x38}

	err := HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedOpenVPN)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, uint8(7), events[0].Opcode)
	require.Equal(t, "P_CONTROL_HARD_RESET_CLIENT_V2", events[0].OpcodeName)
	require.Equal(t, uint8(0), events[0].KeyID)
	require.Empty(t, events[0].SessionID)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleOpenVPNEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}

	err := HandleOpenVPN(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "openvpn", h.produced[0].handler)
	require.Empty(t, h.replies)
}

func TestParseOpenVPNHeaderUnknownOpcode(t *testing.T) {
	frame := parseOpenVPNHeader([]byte{0xf8, 1, 2, 3, 4, 5, 6, 7, 8})
	require.Equal(t, uint8(31), frame.Opcode)
	require.Equal(t, "UNKNOWN", frame.OpcodeName)
	require.Equal(t, uint8(0), frame.KeyID)
	require.Equal(t, "0102030405060708", frame.SessionID)
}

// openVPNScannerProbe is the 13-byte reset seen in the wild: zero session ID,
// no room for both the ack count and the packet ID.
func openVPNScannerProbe() []byte {
	return []byte{0x38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
}

func TestHandleOpenVPNMalformedReset(t *testing.T) {
	viper.Set("openvpn.reply", true)
	t.Cleanup(func() { viper.Set("openvpn.reply", false) })
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 52647}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := openVPNScannerProbe()

	require.NoError(t, HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies, "malformed resets are dropped like a real server would")

	events := h.produced[0].decoded.([]parsedOpenVPN)
	require.Len(t, events, 1)
	require.True(t, events[0].Malformed)
	require.Nil(t, events[0].PacketID)
	require.Equal(t, "0000000000000000", events[0].SessionID)
	require.Equal(t, payload, events[0].Payload)
}

func TestParseOpenVPNResetFields(t *testing.T) {
	frame := parseOpenVPNHeader(openVPNHardResetInternet())
	require.False(t, frame.Malformed)
	require.Equal(t, 0, frame.AckCount)
	require.NotNil(t, frame.PacketID)
	require.Equal(t, uint32(0), *frame.PacketID)

	// one ack: opcode, session, count, ack id, peer session, packet id 5
	data := append([]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1}, 0, 0, 0, 5)
	frame = parseOpenVPNHeader(data)
	require.False(t, frame.Malformed)
	require.Equal(t, 1, frame.AckCount)
	require.Equal(t, uint32(5), *frame.PacketID)

	// ack count claims more than the datagram holds
	frame = parseOpenVPNHeader([]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 3, 0})
	require.True(t, frame.Malformed)
	require.Equal(t, 3, frame.AckCount)
}

func TestHandleOpenVPNReply(t *testing.T) {
	viper.Set("openvpn.reply", true)
	t.Cleanup(func() { viper.Set("openvpn.reply", false) })
	orig := openVPNRandRead
	openVPNRandRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0xa0 + byte(i)
		}
		return len(b), nil
	}
	t.Cleanup(func() { openVPNRandRead = orig })

	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 61611}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1194}
	payload := append([]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0}, 0, 0, 0, 7)

	require.NoError(t, HandleOpenVPN(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Len(t, h.replies, 1)

	want := []byte{
		0x40,                                           // opcode 8, key_id 0
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // server session
		1,          // one ack
		0, 0, 0, 7, // acked client packet ID
		1, 2, 3, 4, 5, 6, 7, 8, // client session
		0, 0, 0, 0, // server packet ID
	}
	require.Equal(t, want, h.replies[0])

	events := h.produced[0].decoded.([]parsedOpenVPN)
	require.Len(t, events, 2)
	require.Equal(t, uint32(7), *events[0].PacketID)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "P_CONTROL_HARD_RESET_SERVER_V2", events[1].Command)
	require.Equal(t, "ok", events[1].Status)
	require.Equal(t, "a0a1a2a3a4a5a6a7", events[1].SessionID)
	require.Equal(t, want, events[1].Payload)
}
