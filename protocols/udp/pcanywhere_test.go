package udp

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/pcanywhere"
)

// Captured datagram (Shodan, 207.90.244.20 -> udp/5632, 2026-11-08): the
// pcAnywhere name query, base64 "TlE=".
var pcAnywhereNameQuery = []byte("NQ")

func pcAnywhereAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("207.90.244.20"), Port: 41234},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5632}
}

func sendPCAnywhere(t *testing.T, h *recordingHoneypot, data []byte) []parsedPCAnywhere {
	t.Helper()
	src, dst := pcAnywhereAddrs()
	require.NoError(t, HandlePCAnywhere(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "pcanywhere", h.produced[0].handler)
	return h.produced[0].decoded.([]parsedPCAnywhere)
}

func TestHandlePCAnywhereNameQuery(t *testing.T) {
	h := &recordingHoneypot{}
	events := sendPCAnywhere(t, h, pcAnywhereNameQuery)

	want := []byte("NRACCT-PC01_______________AHM_3___")
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, pcAnywhereNameQuery, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Equal(t, []parsedPCAnywhere{
		{Direction: "read", Command: "NQ", Payload: pcAnywhereNameQuery},
		{Direction: "write", Command: "NQ", Status: "NR", Payload: want},
	}, events)
}

func TestHandlePCAnywhereStatusQuery(t *testing.T) {
	h := &recordingHoneypot{}
	events := sendPCAnywhere(t, h, []byte("ST"))

	want, _ := pcanywhere.Reply(pcanywhere.StatusQuery, pcanywhere.DefaultPersona)
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, []parsedPCAnywhere{
		{Direction: "read", Command: "ST", Payload: []byte("ST")},
		{Direction: "write", Command: "ST", Status: "available", Payload: want},
	}, events)
}

func TestHandlePCAnywhereUnknown(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("MGLNDD_1.2.3.4_5632\n"),
		{},
		bytes.Repeat([]byte("A"), 2000),
	} {
		h := &recordingHoneypot{}
		events := sendPCAnywhere(t, h, data)
		require.Empty(t, h.replies)
		require.Len(t, events, 1)
		require.Empty(t, events[0].Command)
		require.Equal(t, len(data) > maxPCAnywherePayload, events[0].Truncated)
		require.LessOrEqual(t, len(events[0].Payload), maxPCAnywherePayload)
	}
}

func TestHandlePCAnywhereReplyError(t *testing.T) {
	h := &failingReplyHoneypot{}
	src, dst := pcAnywhereAddrs()
	require.NoError(t, HandlePCAnywhere(context.Background(), src, dst, pcAnywhereNameQuery, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndWriteError, h.produced[0].endReason)
}
