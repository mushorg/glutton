package udp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// stunBinding is the captured Binding Request from 207.90.244.25 to udp/8088
// (run-1793997453-1.jsonl event #3, 2026-11-06).
var stunBinding, _ = hex.DecodeString("000100002112a442307755703271327871716a6a")

func stunAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("207.90.244.25"), Port: 25835},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8088}
}

func TestHandleSTUNBinding(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := stunAddrs()

	require.NoError(t, HandleSTUN(context.Background(), src, dst, stunBinding, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "stun", h.produced[0].handler)
	require.Equal(t, stunBinding, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	resp, _ := hex.DecodeString("010100382112a442307755703271327871716a6a" +
		"00200008000145f9ee48505b" + "00010008000164ebcf5af419" +
		"80220014436f7475726e2d342e362e322027476f72737427" + "80280004a29a2bb6")
	require.Equal(t, [][]byte{resp}, h.replies)
	require.Equal(t, []parsedSTUN{
		{Direction: "read", Command: "binding-request", TransactionID: "307755703271327871716a6a", Payload: stunBinding},
		{Direction: "write", Command: "binding-success", Status: "success", TransactionID: "307755703271327871716a6a",
			Attributes: []string{"xor-mapped-address", "mapped-address", "software", "fingerprint"},
			Software:   "Coturn-4.6.2 'Gorst'", Payload: resp},
	}, h.produced[0].decoded)
}

func TestHandleSTUNAllocateRecordedOnly(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := stunAddrs()
	alloc := append([]byte{}, stunBinding...)
	alloc[1] = 0x03 // allocate request

	require.NoError(t, HandleSTUN(context.Background(), src, dst, alloc, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedSTUN)
	require.Len(t, events, 1)
	require.Equal(t, "allocate-request", events[0].Command)
}

func TestHandleSTUNMalformed(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := stunAddrs()
	short := stunBinding[:10]

	require.NoError(t, HandleSTUN(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSTUN{{Direction: "read", Command: "unknown", Payload: short}}, h.produced[0].decoded)
}

func TestHandleSTUNOversizeTruncated(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := stunAddrs()
	body := make([]byte, 2000)
	body[0], body[1], body[2], body[3] = 0x00, 0x26, 0x07, 0xcc // padding attribute, 1996 bytes
	data := append([]byte{0x00, 0x01, 0x07, 0xd0}, stunBinding[4:20]...)
	data = append(data, body...)

	require.NoError(t, HandleSTUN(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSTUN)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxSTUNPayload)
	require.Equal(t, []string{"padding"}, events[0].Attributes)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPRoutesSTUN(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := stunAddrs()

	require.NoError(t, HandleUDP(context.Background(), src, dst, stunBinding, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "stun", h.produced[0].handler)

	h2 := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("hello world, twenty+ bytes"), connection.Metadata{}, testLogger{}, h2))
	require.Equal(t, "udp", h2.produced[0].handler)
}
