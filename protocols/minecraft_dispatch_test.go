package protocols

import (
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/minecraft"
	"github.com/stretchr/testify/require"
)

// matscan's Handshake + Status Request from Ochi event
// 840d93b6-c4c3-4981-b817-5c46a41b25e2 on tcp/49214; older sensors answered
// it with random bytes from the catch-all.
var matscanPing = []byte{0x0d, 0x00, 0x2f, 0x07, 'm', 'a', 't', 's', 'c', 'a', 'n', 0x05, 0x39, 0x01, 0x01, 0x00}

func TestCatchAllRoutesOffPortMinecraft(t *testing.T) {
	ev := dispatchCatchAll(t, 49214, func(c net.Conn) {
		_, err := c.Write(matscanPing)
		require.NoError(t, err)
		pkt, err := minecraft.ReadPacket(c)
		require.NoError(t, err)
		require.Equal(t, int32(minecraft.IDStatusResp), pkt.ID)
	})
	require.Equal(t, "minecraft", ev.protocol)
	require.Len(t, ev.frames, 3)
	require.Equal(t, "handshake", ev.frames[0]["command"])
	require.Equal(t, "matscan", ev.frames[0]["path"])
	require.EqualValues(t, 47, ev.frames[0]["protocol_version"])
	require.EqualValues(t, 1337, ev.frames[0]["port"])
	require.Equal(t, "status_request", ev.frames[1]["command"])
	require.Equal(t, "write", ev.frames[2]["direction"])
	require.Equal(t, "status_response", ev.frames[2]["status"])
}

func TestCatchAllMinecraftLookalikeStaysTCP(t *testing.T) {
	// valid length prefix and packet ID, but next state 9
	ev := dispatchCatchAll(t, 49214, func(c net.Conn) {
		_, err := c.Write([]byte{0x06, 0x00, 0x00, 0x00, 0x63, 0xdd, 0x09})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
}

func TestCatchAllShortMinecraftPrefixStaysTCP(t *testing.T) {
	// shorter than the declared Handshake: still handled, not dropped
	ev := dispatchCatchAll(t, 49214, func(c net.Conn) {
		_, err := c.Write(matscanPing[:4])
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
	require.Equal(t, "read", ev.frames[0]["direction"])
}

// nmap's legacy server list ping from the tcp/12496 capture (152.32.225[.]99);
// older sensors answered it with random bytes from the catch-all.
var legacyPing = []byte{0xfe, 0x01}

func TestCatchAllRoutesOffPortLegacyMinecraftPing(t *testing.T) {
	var reply []byte
	ev := dispatchCatchAll(t, 12496, func(c net.Conn) {
		_, err := c.Write(legacyPing)
		require.NoError(t, err)
		reply = make([]byte, 3)
		_, err = io.ReadFull(c, reply)
		require.NoError(t, err)
	})
	require.Equal(t, byte(0xff), reply[0])
	require.Equal(t, "minecraft", ev.protocol)
	require.Len(t, ev.frames, 2)
	require.Equal(t, "legacy_ping", ev.frames[0]["command"])
	require.Equal(t, "legacy_status_response", ev.frames[1]["status"])
}

func TestCatchAllLegacyPingPrefixOfHandshakeStaysModern(t *testing.T) {
	// FE 01 00 is the length and ID of a 254-byte Handshake, not a legacy
	// ping; this one is not a valid Handshake, so it stays on the catch-all
	ev := dispatchCatchAll(t, 12496, func(c net.Conn) {
		_, err := c.Write([]byte{0xfe, 0x01, 0x00, 0x00})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
}

// nmap's MQTT 3.1.1 CONNECT (client id "nmap") from the same capture.
var nmapMQTTConnect = []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x04, 'n', 'm', 'a', 'p'}

func TestCatchAllRoutesOffPortMQTT(t *testing.T) {
	var connack []byte
	ev := dispatchCatchAll(t, 12496, func(c net.Conn) {
		_, err := c.Write(nmapMQTTConnect)
		require.NoError(t, err)
		connack = make([]byte, 4)
		_, err = io.ReadFull(c, connack)
		require.NoError(t, err)
	})
	require.Equal(t, []byte{0x20, 0x02}, connack[:2])
	require.Equal(t, "mqtt", ev.protocol)
	require.Equal(t, "CONNECT", ev.frames[0]["command"])
	require.Equal(t, "nmap", ev.frames[0]["client_id"])
}

func TestCatchAllMQTTLookalikeStaysTCP(t *testing.T) {
	// right packet type, wrong protocol name
	ev := dispatchCatchAll(t, 12496, func(c net.Conn) {
		_, err := c.Write([]byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'X', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x04, 'n', 'm', 'a', 'p'})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
}
