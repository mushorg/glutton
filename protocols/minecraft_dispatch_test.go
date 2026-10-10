package protocols

import (
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
