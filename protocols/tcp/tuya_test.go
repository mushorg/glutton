package tcp

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/tuya"
	"github.com/stretchr/testify/require"
)

// DP_QUERY frame (protocol 3.3, encrypted body, valid CRC32) captured on
// tcp/6668 from event 1 of capture run-1793918953-1.
const tuyaCaptureDPQueryHex = "000055aa000000000000000a000000a8" +
	"35baf5463741cbbd845fd96ff9a15aeed12dfe14e26b88ab318cfcdaeb8983fb" +
	"bf5bae5eda35466042ca059b65a007174d399e69b343694b23deddcd10619fcc" +
	"5a56e1250f388e5c2ec96f40adff8e6fa3a3857c8fb7d879f2586a07374fba2d" +
	"90070454e730385635f9249c05a859c38daecae98ce4af2a9410d6dc069da7b3" +
	"0c038f6b7032d1d1ef51307c43f66eceddb3a15cfb5dc0cd0f605ba4382b3f20" +
	"0c950a010000aa55"

func tuyaCaptureDPQuery(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(tuyaCaptureDPQueryHex)
	require.NoError(t, err)
	return b
}

func startTuya(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleTuya(context.Background(), serverConn, connection.Metadata{TargetPort: 6668}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitTuya(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "tuya", produced.protocol)
	return produced, err
}

func TestHandleTuyaCapturedDPQuery(t *testing.T) {
	client, hp, done := startTuya(t)
	capture := tuyaCaptureDPQuery(t)

	_, err := client.Write(capture)
	require.NoError(t, err)
	want := tuya.BuildResponse(0, tuya.CmdDPQuery, 1, tuya.UndecryptableBody)
	reply := make([]byte, len(want))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want, reply)
	require.NoError(t, client.Close())

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, capture, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedTuya{
		{Direction: "read", Command: "dp-query", Checksum: tuya.ChecksumOK, Payload: capture},
		{Direction: "write", Command: "dp-query", Status: "data-unvalid", Payload: reply},
	}, produced.decoded)
}

func TestHandleTuyaHeartbeatEchoesSeq(t *testing.T) {
	client, hp, done := startTuya(t)

	// synthetic: client heartbeat with seq 5, an empty body and a zeroed CRC
	hb, err := hex.DecodeString("000055aa00000005000000090000000800000000" + "0000aa55")
	require.NoError(t, err)
	_, err = client.Write(hb)
	require.NoError(t, err)
	want := tuya.BuildResponse(5, tuya.CmdHeartbeat, 0, nil)
	reply := make([]byte, len(want))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want, reply)
	require.NoError(t, client.Close())

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedTuya{
		{Direction: "read", Command: "heartbeat", Seq: 5, Checksum: tuya.ChecksumMismatch, Payload: hb},
		{Direction: "write", Command: "heartbeat", Seq: 5, Status: "heartbeat", Payload: reply},
	}, produced.decoded)
}

func TestHandleTuyaBadPrefix(t *testing.T) {
	client, hp, done := startTuya(t)

	probe := []byte("GET / HTTP/1.1\r\n")
	_, err := client.Write(probe)
	require.NoError(t, err)

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedTuya{{Direction: "read", Payload: probe}}, produced.decoded)
}

func TestHandleTuyaOversize(t *testing.T) {
	client, hp, done := startTuya(t)

	header := tuyaCaptureDPQuery(t)[:tuya.HeaderLen]
	header[12], header[13], header[14], header[15] = 0x00, 0x10, 0x00, 0x00 // 1 MiB
	go func() {
		_, _ = client.Write(header)
		_, _ = client.Write(make([]byte, tuyaMaxBody))
	}()

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndReadError, produced.endReason)
	frames := produced.decoded.([]parsedTuya)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Len(t, frames[0].Payload, tuya.HeaderLen+tuyaMaxBody)
}

func TestHandleTuyaEarlyDisconnect(t *testing.T) {
	client, hp, done := startTuya(t)
	capture := tuyaCaptureDPQuery(t)

	_, err := client.Write(capture[:40])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedTuya{{Direction: "read", Command: "dp-query", Payload: capture[:40]}}, produced.decoded)
}

func TestHandleTuyaNoData(t *testing.T) {
	client, hp, done := startTuya(t)
	require.NoError(t, client.Close())

	produced, err := waitTuya(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
}
