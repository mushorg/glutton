package tcp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/bgp"
	"github.com/stretchr/testify/require"
)

// bgpShodanOpen is the 29-byte OPEN captured from two Shodan sources on
// tcp/179 (run-1793745705 events #50/#51): version 4, AS 19384, hold time
// 180, BGP ID 216.117.2.180, no optional parameters.
var bgpShodanOpen = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x1d, 0x01, 0x04, 0x4b, 0xb8, 0x00, 0xb4,
	0xd8, 0x75, 0x02, 0xb4, 0x00,
}

func startBGP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleBGP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return client, hp, done
}

func waitBGP(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	produced := waitProduced(t, hp)
	require.NoError(t, <-done)
	require.Equal(t, "bgp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("unexpected second event: %+v", extra)
	default:
	}
	return produced
}

func readBGPMessage(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_, raw, err := bgp.ReadMessage(conn)
	require.NoError(t, err)
	return raw
}

func TestHandleBGPShodanOpen(t *testing.T) {
	client, hp, done := startBGP(t)

	_, err := client.Write(bgpShodanOpen)
	require.NoError(t, err)
	open := readBGPMessage(t, client)
	keepalive := readBGPMessage(t, client)

	// The session continues: a KEEPALIVE is answered with a KEEPALIVE.
	_, err = client.Write(bgp.BuildKeepalive())
	require.NoError(t, err)
	require.Equal(t, bgp.BuildKeepalive(), readBGPMessage(t, client))
	require.NoError(t, client.Close())

	wantOpen := bgp.BuildOpen(bgpLocalAS, bgpHoldTime, bgpFallbackRouterID)
	require.Equal(t, wantOpen, open)
	require.Equal(t, bgp.BuildKeepalive(), keepalive)

	produced := waitBGP(t, hp, done)
	require.Equal(t, bgpShodanOpen, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	kaHeader := bgp.Header{Length: 19, Type: bgp.TypeKeepalive}
	require.Equal(t, []parsedBGP{
		{
			Direction: "read",
			Header:    bgp.Header{Length: 29, Type: bgp.TypeOpen},
			Command:   "OPEN",
			Open:      &bgp.Open{Version: 4, AS: 19384, HoldTime: 180, BGPID: "216.117.2.180"},
			Payload:   bgpShodanOpen,
		},
		{Direction: "write", Header: bgp.Header{Length: uint16(len(wantOpen)), Type: bgp.TypeOpen}, Command: "OPEN", Status: "open", Payload: wantOpen},
		{Direction: "write", Header: kaHeader, Command: "KEEPALIVE", Status: "keepalive", Payload: bgp.BuildKeepalive()},
		{Direction: "read", Header: kaHeader, Command: "KEEPALIVE", Payload: bgp.BuildKeepalive()},
		{Direction: "write", Header: kaHeader, Command: "KEEPALIVE", Status: "keepalive", Payload: bgp.BuildKeepalive()},
	}, produced.decoded)
}

func TestHandleBGPBadMarker(t *testing.T) {
	client, hp, done := startBGP(t)

	junk := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() { _, _ = client.Write(junk) }() // handler stops after the header
	notification := readBGPMessage(t, client)
	want := bgp.BuildNotification(bgp.ErrCodeHeader, bgp.SubConnectionNotSynchronized, nil)
	require.Equal(t, want, notification)

	produced := waitBGP(t, hp, done)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedBGP{
		{Direction: "read", Payload: junk[:bgp.HeaderLen]},
		{
			Direction:    "write",
			Header:       bgp.Header{Length: 21, Type: bgp.TypeNotification},
			Command:      "NOTIFICATION",
			Notification: &bgp.Notification{Code: 1, Subcode: 1},
			Status:       "notification",
			Payload:      want,
		},
	}, produced.decoded)
}

func TestHandleBGPOversizeLength(t *testing.T) {
	client, hp, done := startBGP(t)

	hdr := append(bytes.Repeat([]byte{0xff}, 16), 0xff, 0xff, bgp.TypeUpdate) // 65535 declared
	_, err := client.Write(hdr)
	require.NoError(t, err)
	require.Equal(t, bgp.BuildNotification(bgp.ErrCodeHeader, bgp.SubBadMessageLength, []byte{0xff, 0xff}), readBGPMessage(t, client))

	produced := waitBGP(t, hp, done)
	frames := produced.decoded.([]parsedBGP)
	require.Len(t, frames, 2)
	require.Equal(t, hdr, frames[0].Payload)
	require.Equal(t, connection.EndReadError, produced.endReason)
}

func TestHandleBGPUnsupportedVersion(t *testing.T) {
	client, hp, done := startBGP(t)

	open := append([]byte(nil), bgpShodanOpen...)
	open[19] = 3
	_, err := client.Write(open)
	require.NoError(t, err)
	require.Equal(t, bgp.BuildNotification(bgp.ErrCodeOpen, bgp.SubUnsupportedVersion, []byte{0, 4}), readBGPMessage(t, client))

	produced := waitBGP(t, hp, done)
	frames := produced.decoded.([]parsedBGP)
	require.Len(t, frames, 2)
	require.Equal(t, uint8(3), frames[0].Open.Version)
	require.Equal(t, "notification", frames[1].Status)
}

func TestHandleBGPKeepaliveBeforeOpen(t *testing.T) {
	client, hp, done := startBGP(t)

	_, err := client.Write(bgp.BuildKeepalive())
	require.NoError(t, err)
	require.Equal(t, bgp.BuildNotification(bgp.ErrCodeFSM, 0, nil), readBGPMessage(t, client))

	produced := waitBGP(t, hp, done)
	require.Len(t, produced.decoded.([]parsedBGP), 2)
}

func TestHandleBGPClientNotification(t *testing.T) {
	client, hp, done := startBGP(t)

	_, err := client.Write(bgpShodanOpen)
	require.NoError(t, err)
	readBGPMessage(t, client)
	readBGPMessage(t, client)
	cease := bgp.BuildNotification(bgp.ErrCodeCease, 2, nil)
	_, err = client.Write(cease)
	require.NoError(t, err)

	produced := waitBGP(t, hp, done)
	frames := produced.decoded.([]parsedBGP)
	require.Len(t, frames, 4)
	require.Equal(t, parsedBGP{
		Direction:    "read",
		Header:       bgp.Header{Length: 21, Type: bgp.TypeNotification},
		Command:      "NOTIFICATION",
		Notification: &bgp.Notification{Code: 6, Subcode: 2, Data: []byte{}},
		Payload:      cease,
	}, frames[3])
}

func TestHandleBGPTruncatedHeader(t *testing.T) {
	client, hp, done := startBGP(t)

	_, err := client.Write(bgpShodanOpen[:10])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced := waitBGP(t, hp, done)
	require.Equal(t, []parsedBGP{{Direction: "read", Payload: bgpShodanOpen[:10]}}, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleBGPNoData(t *testing.T) {
	client, hp, done := startBGP(t)
	require.NoError(t, client.Close())

	produced := waitBGP(t, hp, done)
	require.Empty(t, produced.decoded)
}
