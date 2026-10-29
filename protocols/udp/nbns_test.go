package udp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers/netbios"
	"github.com/stretchr/testify/require"
)

// 2026-10-29 capture: Shodan NBSTAT wildcard query to udp/137 (50 bytes).
var nbnsShodan, _ = hex.DecodeString("80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")

func nbnsAddrs(dst net.IP) (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("143.198.238.87"), Port: 19872},
		&net.UDPAddr{IP: dst, Port: 137}
}

func TestHandleNBNSShodan(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := nbnsAddrs(net.ParseIP("1.2.3.4"))
	require.NoError(t, HandleNBNS(context.Background(), src, dst, nbnsShodan, connection.Metadata{}, testLogger{}, h))

	require.Len(t, h.replies, 1)
	resp := h.replies[0]
	require.Equal(t, []byte{0x80, 0xf0}, resp[0:2])
	require.Equal(t, []byte{0x84, 0x00}, resp[2:4], "response, authoritative")
	require.Less(t, len(resp), 4*len(nbnsShodan)+40, "three names, not a large table")
	require.True(t, bytes.Contains(resp, []byte("SERVER")))
	require.True(t, bytes.Contains(resp, []byte("WORKGROUP")))
	require.True(t, bytes.Contains(resp, []byte{0x02, 0x00, 0x01, 0x02, 0x03, 0x04}))

	require.Len(t, h.produced, 1)
	require.Equal(t, "nbns", h.produced[0].handler)
	require.Equal(t, nbnsShodan, h.produced[0].payload)
	events := h.produced[0].decoded.([]parsedNBNS)
	require.Equal(t, []parsedNBNS{
		{
			Direction: "read",
			Command:   "NBSTAT",
			Path:      "*<00>",
			TXID:      0x80f0,
			Payload:   nbnsShodan,
		},
		{
			Direction: "write",
			Command:   "NBSTAT",
			Path:      "*<00>",
			TXID:      0x80f0,
			Status:    "NBSTAT",
			Payload:   resp,
		},
	}, events)
}

func TestHandleNBNSNameQuery(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := nbnsAddrs(net.ParseIP("10.1.2.3"))
	q := append(netbios.Encode("SERVER", 0x20), 0x00, 0x20, 0x00, 0x01)
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 0x1111)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	pkt = append(pkt, q...)

	require.NoError(t, HandleNBNS(context.Background(), src, dst, pkt, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.Equal(t, []byte{10, 1, 2, 3}, h.replies[0][len(h.replies[0])-4:])
	events := h.produced[0].decoded.([]parsedNBNS)
	require.Equal(t, "NB", events[0].Command)
	require.Equal(t, "SERVER<20>", events[0].Path)
	require.Equal(t, "NB", events[1].Status)

	// a name that is not ours is recorded and not answered
	h = &recordingHoneypot{}
	other := append(netbios.Encode("PRINTER", 0x00), 0x00, 0x20, 0x00, 0x01)
	pkt = append(pkt[:12], other...)
	require.NoError(t, HandleNBNS(context.Background(), src, dst, pkt, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events = h.produced[0].decoded.([]parsedNBNS)
	require.Len(t, events, 1)
	require.Equal(t, "PRINTER<00>", events[0].Path)
}

func TestHandleNBNSNoReply(t *testing.T) {
	src, dst := nbnsAddrs(net.ParseIP("1.2.3.4"))

	resp := append([]byte{}, nbnsShodan...)
	resp[2] |= 0x80 // QR
	h := &recordingHoneypot{}
	require.NoError(t, HandleNBNS(context.Background(), src, dst, resp, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies, "response packets are not answered")

	h = &recordingHoneypot{}
	_, bcast := nbnsAddrs(net.IPv4bcast)
	require.NoError(t, HandleNBNS(context.Background(), src, bcast, nbnsShodan, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies, "a broadcast destination is not answered")

	h = &recordingHoneypot{}
	reg := make([]byte, 12)
	binary.BigEndian.PutUint16(reg[0:2], 0x2222)
	binary.BigEndian.PutUint16(reg[2:4], 0x2800) // opcode registration
	require.NoError(t, HandleNBNS(context.Background(), src, dst, reg, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedNBNS)
	require.Equal(t, "REGISTRATION", events[0].Command)
	require.Equal(t, uint16(0x2222), events[0].TXID)

	h = &recordingHoneypot{}
	short := []byte{0x01, 0x02, 0x03}
	require.NoError(t, HandleNBNS(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events = h.produced[0].decoded.([]parsedNBNS)
	require.Equal(t, []parsedNBNS{{Direction: "read", Command: "UNKNOWN", Payload: short}}, events)

	h = &recordingHoneypot{}
	bad := append([]byte{}, nbnsShodan...)
	bad[12] = 0x10 // not a first-level name
	require.NoError(t, HandleNBNS(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events = h.produced[0].decoded.([]parsedNBNS)
	require.Equal(t, "UNKNOWN", events[0].Command)
}
