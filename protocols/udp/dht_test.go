package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/dht"
	"github.com/stretchr/testify/require"
)

// Captured Shodan find_node on udp/6881
// (Ochi event ead994ab-d411-4a68-b117-8f827a383583).
var dhtRead1 = []byte("d1:ad2:id20:jBhdHDWPdv2RGzRKGACQ6:target20:zCcWO8VeKHZSTasDKxbf4:want4:n4n6e1:q9:find_node1:t2:rf1:y1:qe")

func dhtAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("64.23.214.73"), Port: 16086},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 6881}
}

func TestHandleDHTFindNode(t *testing.T) {
	var ourID [dht.NodeIDLen]byte
	copy(ourID[:], []byte("0123456789abcdefghij"))
	dhtOurID = ourID

	h := &recordingHoneypot{}
	src, dst := dhtAddrs()

	require.NoError(t, HandleDHT(context.Background(), src, dst, dhtRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "dht", h.produced[0].handler)
	require.Equal(t, dhtRead1, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(dhtRead1))

	events, ok := h.produced[0].decoded.([]parsedDHT)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, parsedDHT{
		Direction:   "read",
		Command:     "find_node",
		NodeID:      dht.Hex([]byte("jBhdHDWPdv2RGzRKGACQ")),
		Target:      dht.Hex([]byte("zCcWO8VeKHZSTasDKxbf")),
		Want:        "n4,n6",
		Transaction: dht.Hex([]byte("rf")),
		Payload:     dhtRead1,
	}, events[0])
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "find_node", events[1].Command)
	require.Equal(t, "response", events[1].Status)
	require.Equal(t, dht.Hex(ourID[:]), events[1].NodeID)
	require.Equal(t, dht.Hex([]byte("rf")), events[1].Transaction)
	require.Equal(t, h.replies[0], events[1].Payload)
	require.Contains(t, string(events[1].Payload), "5:nodes")
}

func TestHandleDHTPing(t *testing.T) {
	var ourID [dht.NodeIDLen]byte
	copy(ourID[:], []byte("0123456789abcdefghij"))
	dhtOurID = ourID

	req := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	h := &recordingHoneypot{}
	src, dst := dhtAddrs()
	require.NoError(t, HandleDHT(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(req))
	events := h.produced[0].decoded.([]parsedDHT)
	require.Equal(t, "ping", events[0].Command)
	require.Equal(t, "response", events[1].Status)
}

func TestHandleDHTGetPeers(t *testing.T) {
	var ourID [dht.NodeIDLen]byte
	copy(ourID[:], []byte("0123456789abcdefghij"))
	dhtOurID = ourID

	req := []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:bb1:y1:qe")
	h := &recordingHoneypot{}
	src, dst := dhtAddrs()
	require.NoError(t, HandleDHT(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedDHT)
	require.Equal(t, "get_peers", events[0].Command)
	require.Equal(t, dht.Hex([]byte("mnopqrstuvwxyz123456")), events[0].InfoHash)
	require.Equal(t, "response", events[1].Status)
	require.Contains(t, string(h.replies[0]), "5:token")
}

func TestHandleDHTAnnouncePeer(t *testing.T) {
	req := []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token2:gte1:q13:announce_peer1:t2:cc1:y1:qe")
	h := &recordingHoneypot{}
	src, dst := dhtAddrs()
	require.NoError(t, HandleDHT(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedDHT)
	require.Equal(t, "announce_peer", events[0].Command)
	require.Equal(t, 6881, events[0].Port)
	require.Equal(t, "response", events[1].Status)
}

func TestHandleDHTMalformed(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := dhtAddrs()
	bad := []byte("d1:a1:be")
	require.NoError(t, HandleDHT(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedDHT{{Direction: "read", Command: "unknown", Payload: bad}}, h.produced[0].decoded)
}

func TestHandleDHTRoutedFromCatchAll(t *testing.T) {
	src, dst := dhtAddrs()
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, dhtRead1, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "dht", h.produced[0].handler)

	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("not-dht"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}
