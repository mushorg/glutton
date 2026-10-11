package protocols

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/spice"
	"github.com/stretchr/testify/require"
)

// SPICE link message with no caps for the main channel, sent to tcp/5907 in
// Ochi event a1089002-b561-402e-8143-7cfe51e439ac.
var spiceScannerProbe = []byte("REDQ\x02\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00")

// readSPICELinkReply reads the server's link reply and checks it accepts.
func readSPICELinkReply(t *testing.T, c net.Conn) {
	t.Helper()
	head := make([]byte, spice.HeaderLen)
	_, err := io.ReadFull(c, head)
	require.NoError(t, err)
	body := make([]byte, binary.LittleEndian.Uint32(head[12:]))
	_, err = io.ReadFull(c, body)
	require.NoError(t, err)
	r, err := spice.ParseLinkReply(append(head, body...))
	require.NoError(t, err)
	require.Equal(t, uint32(spice.LinkErrOK), r.Error)
}

func TestRFBTargetRoutesSPICE(t *testing.T) {
	names := dispatchTarget(t, "rfb", 5907, func(c net.Conn) {
		_, err := c.Write(spiceScannerProbe)
		require.NoError(t, err)
		readSPICELinkReply(t, c)
	})
	require.Equal(t, []string{"spice"}, names)
}

func TestRFBTargetSilentClientGetsRFB(t *testing.T) {
	names := dispatchTarget(t, "rfb", 5900, func(c net.Conn) {
		banner := make([]byte, 12)
		_, err := io.ReadFull(c, banner)
		require.NoError(t, err)
		require.Equal(t, "RFB 003.008\n", string(banner))
	})
	require.Equal(t, []string{"rfb"}, names)
}

func TestRFBTargetEarlyRFBClientStaysRFB(t *testing.T) {
	// a client that sends its version before the banner is still RFB
	names := dispatchTarget(t, "rfb", 5900, func(c net.Conn) {
		_, err := c.Write([]byte("RFB 003.008\n"))
		require.NoError(t, err)
		banner := make([]byte, 12)
		_, err = io.ReadFull(c, banner)
		require.NoError(t, err)
		require.Equal(t, "RFB 003.008\n", string(banner))
	})
	require.Equal(t, []string{"rfb"}, names)
}

func TestCatchAllRoutesOffPortSPICE(t *testing.T) {
	ev := dispatchCatchAll(t, 5907, func(c net.Conn) {
		_, err := c.Write(spiceScannerProbe)
		require.NoError(t, err)
		readSPICELinkReply(t, c)
	})
	require.Equal(t, "spice", ev.protocol)
	require.Equal(t, "LinkMess", ev.frames[0]["command"])
	require.Equal(t, "main", ev.frames[0]["channel_type"])
	require.Equal(t, "OK", ev.frames[1]["status"])
}

func TestCatchAllNonSPICEStaysTCP(t *testing.T) {
	ev := dispatchCatchAll(t, 5907, func(c net.Conn) {
		_, err := c.Write([]byte("REDX\x02\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00"))
		require.NoError(t, err)
		_, err = c.Read(make([]byte, 4096))
		require.NoError(t, err)
	})
	require.Equal(t, "tcp", ev.protocol)
}
