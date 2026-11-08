package udp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/sadp"
)

// Captured datagram (driftnet.io, 193.163.125.68 -> udp/37020, 2026-11-08,
// run-1794168565-2.jsonl event 3).
var sadpRead1 = []byte(`<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>7b1afb58-5904-4d9c-b0ef-090a5ea307f8</Uuid><Types>inquiry</Types></Probe>`)

func sadpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("193.163.125.68"), Port: 19562},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 37020}
}

func withSADPNow(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, 11, 8, 20, 11, 29, 0, time.UTC)
	orig := sadpNow
	sadpNow = func() time.Time { return now }
	t.Cleanup(func() { sadpNow = orig })
	return now
}

func sendSADP(t *testing.T, h *recordingHoneypot, data []byte) []parsedSADP {
	t.Helper()
	src, dst := sadpAddrs()
	require.NoError(t, HandleSADP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "sadp", h.produced[0].handler)
	return h.produced[0].decoded.([]parsedSADP)
}

func TestHandleSADPInquiry(t *testing.T) {
	now := withSADPNow(t)
	h := &recordingHoneypot{}
	events := sendSADP(t, h, sadpRead1)

	uuid := "7b1afb58-5904-4d9c-b0ef-090a5ea307f8"
	want := sadp.BuildProbeMatch(sadp.Request{Uuid: uuid, Types: "inquiry"}, sadp.DeviceFor([]byte("198.51.100.1")), now)
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, sadpRead1, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Equal(t, []parsedSADP{
		{Direction: "read", Command: "inquiry", UUID: uuid, Payload: sadpRead1},
		{Direction: "write", Command: "inquiry", UUID: uuid, Status: "ProbeMatch", Payload: want},
	}, events)
}

func TestHandleSADPRecordsOnly(t *testing.T) {
	withSADPNow(t)
	for _, tc := range []struct {
		data []byte
		want parsedSADP
	}{
		{[]byte(`<Probe><Uuid>u1</Uuid><Types>activate</Types><Password>Admin12345</Password></Probe>`),
			parsedSADP{Direction: "read", Command: "activate", UUID: "u1", Password: "Admin12345"}},
		{[]byte("garbage"), parsedSADP{Direction: "read", Command: "unknown"}},
		{[]byte{}, parsedSADP{Direction: "read", Command: "unknown"}},
	} {
		h := &recordingHoneypot{}
		events := sendSADP(t, h, tc.data)
		require.Empty(t, h.replies)
		tc.want.Payload = tc.data
		require.Equal(t, []parsedSADP{tc.want}, events)
	}
}

func TestHandleSADPCapsPayload(t *testing.T) {
	withSADPNow(t)
	h := &recordingHoneypot{}
	data := append(append([]byte{}, sadpRead1...), bytes.Repeat([]byte(" "), 4096)...)
	events := sendSADP(t, h, data)
	require.Len(t, events[0].Payload, maxSADPPayload)
	require.True(t, events[0].Truncated)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPRoutesSADP(t *testing.T) {
	withSADPNow(t)
	h := &recordingHoneypot{}
	src, _ := sadpAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 40000}

	require.NoError(t, HandleUDP(context.Background(), src, dst, sadpRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "sadp", h.produced[0].handler)

	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}
	require.NoError(t, HandleUDP(context.Background(), other, dst, []byte("<html>probe</html>"), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 2)
	require.Equal(t, "udp", h.produced[1].handler)
}
