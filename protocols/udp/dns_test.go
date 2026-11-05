package udp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// dnsCapturedAnyEDNS is the 37-byte query from 45.198.224.251 to udp/53 on
// 2026-11-05: ID 0x1271, RD set, ANY wisc.edu IN, OPT with UDP size 8192 and DO.
var dnsCapturedAnyEDNS = []byte{
	0x12, 0x71, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x04, 'w', 'i', 's', 'c', 0x03, 'e', 'd', 'u', 0x00, 0x00, 0xff, 0x00, 0x01,
	0x00, 0x00, 0x29, 0x20, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
}

func dnsAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("45.198.224.251"), Port: 58513},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53}
}

func runDNS(t *testing.T, data []byte) (*recordingHoneypot, []parsedDNS) {
	t.Helper()
	h := &recordingHoneypot{}
	src, dst := dnsAddrs()
	require.NoError(t, HandleDNS(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "dns", h.produced[0].handler)
	events, ok := h.produced[0].decoded.([]parsedDNS)
	require.True(t, ok)
	return h, events
}

func TestHandleDNSCapturedAnyEDNS(t *testing.T) {
	h, events := runDNS(t, dnsCapturedAnyEDNS)
	require.Equal(t, dnsCapturedAnyEDNS, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	want := []byte{
		0x12, 0x71, 0x81, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // QR RD, REFUSED
		0x04, 'w', 'i', 's', 'c', 0x03, 'e', 'd', 'u', 0x00, 0x00, 0xff, 0x00, 0x01,
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OPT, 1232, no DO
	}
	require.Equal(t, []parsedDNS{
		{Direction: "read", ID: 0x1271, Command: "ANY", Path: "wisc.edu", Payload: dnsCapturedAnyEDNS},
		{Direction: "write", ID: 0x1271, Status: "REFUSED", Payload: want},
	}, events)
	require.Equal(t, [][]byte{want}, h.replies)
	// non-amplifying: ID echoed and the reply is no larger than the query
	require.Equal(t, binary.BigEndian.Uint16(dnsCapturedAnyEDNS), binary.BigEndian.Uint16(h.replies[0]))
	require.LessOrEqual(t, len(h.replies[0]), len(dnsCapturedAnyEDNS))
}

func TestHandleDNSPlainQueryNoEDNS(t *testing.T) {
	q := []byte{
		0xab, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
	}
	h, events := runDNS(t, q)
	require.Len(t, events, 2)
	require.Equal(t, parsedDNS{Direction: "read", ID: 0xabcd, Command: "TXT", Class: "CH", Path: "version.bind", Payload: q}, events[0])
	require.Equal(t, "REFUSED", events[1].Status)
	require.Len(t, h.replies, 1)
	require.Len(t, h.replies[0], len(q))
	require.Equal(t, []byte{0xab, 0xcd, 0x80, 0x05}, h.replies[0][:4])
}

func TestHandleDNSMalformedQuestion(t *testing.T) {
	// header claims one question, but the label runs past the datagram
	q := []byte{0x00, 0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 'a'}
	h, events := runDNS(t, q)
	require.Equal(t, []parsedDNS{
		{Direction: "read", ID: 7, Payload: q},
		{Direction: "write", ID: 7, Status: "FORMERR", Payload: h.replies[0]},
	}, events)
	require.Equal(t, []byte{0x00, 0x07, 0x81, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}, h.replies[0])
}

func TestHandleDNSShortDatagram(t *testing.T) {
	q := []byte{0x12, 0x71, 0x01}
	h, events := runDNS(t, q)
	require.Equal(t, []parsedDNS{{Direction: "read", Payload: q}}, events)
	require.Empty(t, h.replies)
}

func TestHandleDNSResponseNotAnswered(t *testing.T) {
	q := append([]byte(nil), dnsCapturedAnyEDNS...)
	q[2] |= 0x80 // QR: a response, possibly reflected from another server
	h, events := runDNS(t, q)
	require.Len(t, events, 1)
	require.Equal(t, "ANY", events[0].Command)
	require.Empty(t, h.replies)
}

func TestHandleDNSOversizeTruncated(t *testing.T) {
	q := append(append([]byte(nil), dnsCapturedAnyEDNS...), make([]byte, 2000)...)
	h, events := runDNS(t, q)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxDNSPayload)
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(dnsCapturedAnyEDNS))
}

func TestHandleDNSEmpty(t *testing.T) {
	h, events := runDNS(t, nil)
	require.Empty(t, events)
	require.Empty(t, h.replies)
}
