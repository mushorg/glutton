package dht

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Shodan find_node on udp/6881 (Ochi event ead994ab-d411-4a68-b117-8f827a383583).
var shodanFindNode = []byte("d1:ad2:id20:jBhdHDWPdv2RGzRKGACQ6:target20:zCcWO8VeKHZSTasDKxbf4:want4:n4n6e1:q9:find_node1:t2:rf1:y1:qe")

func TestLooksLikeDHT(t *testing.T) {
	require.True(t, LooksLikeDHT(shodanFindNode))
	require.False(t, LooksLikeDHT([]byte("hello")))
	require.False(t, LooksLikeDHT([]byte("d1:a1:be")))
	require.False(t, LooksLikeDHT([]byte{0xff, 0xff, 0xff, 0xff, 'T'}))
}

func TestParseQueryShodanFindNode(t *testing.T) {
	q, err := ParseQuery(shodanFindNode)
	require.NoError(t, err)
	require.Equal(t, MethodFindNode, q.Method)
	require.Equal(t, []byte("rf"), q.Transaction)
	require.Equal(t, []byte("jBhdHDWPdv2RGzRKGACQ"), q.ID)
	require.Equal(t, []byte("zCcWO8VeKHZSTasDKxbf"), q.Target)
	require.Equal(t, []string{"n4", "n6"}, q.Want)
}

func TestParseQueryPing(t *testing.T) {
	raw := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	q, err := ParseQuery(raw)
	require.NoError(t, err)
	require.Equal(t, MethodPing, q.Method)
	require.Equal(t, []byte("aa"), q.Transaction)
}

func TestParseQueryGetPeers(t *testing.T) {
	raw := []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe")
	q, err := ParseQuery(raw)
	require.NoError(t, err)
	require.Equal(t, MethodGetPeers, q.Method)
	require.Equal(t, []byte("mnopqrstuvwxyz123456"), q.InfoHash)
}

func TestParseQueryAnnouncePeer(t *testing.T) {
	raw := []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token2:gte1:q13:announce_peer1:t2:aa1:y1:qe")
	q, err := ParseQuery(raw)
	require.NoError(t, err)
	require.Equal(t, MethodAnnouncePeer, q.Method)
	require.Equal(t, 6881, q.Port)
	require.Equal(t, []byte("gt"), q.Token)
}

func TestParseQueryRejectsResponse(t *testing.T) {
	raw := []byte("d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re")
	_, err := ParseQuery(raw)
	require.ErrorIs(t, err, ErrNotQuery)
}

func TestBuildResponseFindNodeFitsRequest(t *testing.T) {
	q, err := ParseQuery(shodanFindNode)
	require.NoError(t, err)
	var ourID [NodeIDLen]byte
	copy(ourID[:], []byte("0123456789abcdefghij"))
	self := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 6881}

	resp := BuildResponse(q, ourID, self, len(shodanFindNode))
	require.NotNil(t, resp)
	require.LessOrEqual(t, len(resp), len(shodanFindNode))
	require.Contains(t, string(resp), "1:y1:r")
	require.Contains(t, string(resp), "1:t2:rf")
	require.Contains(t, string(resp), "5:nodes")
	require.Contains(t, string(resp), "6:nodes6")
}

func TestBuildResponseNoAmplification(t *testing.T) {
	q, err := ParseQuery([]byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"))
	require.NoError(t, err)
	var ourID [NodeIDLen]byte
	copy(ourID[:], []byte("0123456789abcdefghij"))
	self := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 6881}

	resp := BuildResponse(q, ourID, self, 1)
	require.Nil(t, resp)
}

func TestCompactNode4(t *testing.T) {
	var id [NodeIDLen]byte
	copy(id[:], []byte("0123456789abcdefghij"))
	n := CompactNode4(id, net.ParseIP("198.51.100.1"), 6881)
	require.Len(t, n, CompactNode4Len)
	require.Equal(t, id[:], n[:20])
	require.Equal(t, []byte{198, 51, 100, 1}, n[20:24])
	require.Equal(t, []byte{0x1a, 0xe1}, n[24:])
}
