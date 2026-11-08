package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/gearman"
	"github.com/stretchr/testify/require"
)

// Captured Censys probe on tcp/4730 (run-1794151704-1.jsonl event #3).
var gearmanCapturedEcho = []byte{0x00, 0x52, 0x45, 0x51, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x2a}

func startGearman(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleGearman(context.Background(), serverConn, connection.Metadata{TargetPort: 4730}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitGearmanEvent(t *testing.T, hp *fakeHoneypot, done chan error) []parsedGearman {
	t.Helper()
	require.NoError(t, <-done)
	select {
	case ev := <-hp.produced:
		require.Equal(t, "gearman", ev.protocol)
		frames, ok := ev.decoded.([]parsedGearman)
		require.True(t, ok)
		if len(frames) > 0 {
			require.Equal(t, frames[0].Payload, ev.payload)
		}
		select {
		case <-hp.produced:
			t.Fatal("expected exactly one produced event")
		default:
		}
		return frames
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced Gearman event")
		return nil
	}
}

func TestHandleGearmanCapturedEcho(t *testing.T) {
	client, hp, done := startGearman(t)
	_, err := client.Write(gearmanCapturedEcho)
	require.NoError(t, err)

	reply := make([]byte, 13)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	want := []byte{0x00, 'R', 'E', 'S', 0, 0, 0, 17, 0, 0, 0, 1, '*'}
	require.Equal(t, want, reply)

	require.NoError(t, client.Close())
	frames := waitGearmanEvent(t, hp, done)
	require.Equal(t, []parsedGearman{
		{Direction: "read", Mode: "binary", Command: "ECHO_REQ", PacketType: 16, Payload: gearmanCapturedEcho},
		{Direction: "write", Mode: "binary", Command: "ECHO_RES", PacketType: 17, Payload: want},
	}, frames)
}

func TestHandleGearmanSubmitJob(t *testing.T) {
	client, hp, done := startGearman(t)
	req := gearman.Encode(gearman.MagicReq, gearman.SubmitJobBg, []byte("exec"), []byte("u-1"), []byte("id"))
	_, err := client.Write(req)
	require.NoError(t, err)
	p, err := gearman.ReadPacket(client)
	require.NoError(t, err)
	require.Equal(t, gearman.JobCreated, p.Type)
	require.Equal(t, "H:"+gearmanJobHost+":1", p.Handle())

	require.NoError(t, client.Close())
	frames := waitGearmanEvent(t, hp, done)
	require.Len(t, frames, 2)
	require.Equal(t, parsedGearman{
		Direction: "read", Mode: "binary", Command: "SUBMIT_JOB_BG", PacketType: 18,
		Function: "exec", Unique: "u-1", Payload: req,
	}, frames[0])
	require.Equal(t, "JOB_CREATED", frames[1].Command)
	require.Equal(t, "H:"+gearmanJobHost+":1", frames[1].Handle)
}

func TestHandleGearmanAdminText(t *testing.T) {
	client, hp, done := startGearman(t)
	r := bufio.NewReader(client)
	_, err := client.Write([]byte("version\n"))
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "OK 1.1.19.1\n", line)

	_, err = client.Write([]byte("status\r\n"))
	require.NoError(t, err)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, ".\n", line)

	require.NoError(t, client.Close())
	frames := waitGearmanEvent(t, hp, done)
	require.Equal(t, []parsedGearman{
		{Direction: "read", Mode: "text", Command: "version", Payload: []byte("version\n")},
		{Direction: "write", Mode: "text", Command: "version", Payload: []byte("OK 1.1.19.1\n")},
		{Direction: "read", Mode: "text", Command: "status", Payload: []byte("status\r\n")},
		{Direction: "write", Mode: "text", Command: "status", Payload: []byte(".\n")},
	}, frames)
}

func TestHandleGearmanEarlyDisconnect(t *testing.T) {
	client, hp, done := startGearman(t)
	require.NoError(t, client.Close())
	require.Empty(t, waitGearmanEvent(t, hp, done))
}

func TestHandleGearmanTruncatedHeader(t *testing.T) {
	client, hp, done := startGearman(t)
	_, err := client.Write(gearmanCapturedEcho[:6])
	require.NoError(t, err)
	require.NoError(t, client.Close())
	frames := waitGearmanEvent(t, hp, done)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Equal(t, gearmanCapturedEcho[:6], frames[0].Payload)
}

func TestHandleGearmanOversizeAndBadMagic(t *testing.T) {
	client, hp, done := startGearman(t)
	hdr := make([]byte, gearman.HeaderSize)
	copy(hdr, gearman.MagicReq)
	binary.BigEndian.PutUint32(hdr[4:8], gearman.SubmitJob)
	binary.BigEndian.PutUint32(hdr[8:12], gearman.MaxBodySize+1)
	_, err := client.Write(hdr)
	require.NoError(t, err)
	frames := waitGearmanEvent(t, hp, done)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Equal(t, hdr, frames[0].Payload)

	client, hp, done = startGearman(t)
	bad := append([]byte{0x00, 'X', 'Y', 'Z'}, make([]byte, 8)...)
	_, err = client.Write(bad)
	require.NoError(t, err)
	frames = waitGearmanEvent(t, hp, done)
	require.Len(t, frames, 1)
	require.Equal(t, bad, frames[0].Payload)
}

func TestHandleGearmanLongLineCapped(t *testing.T) {
	client, hp, done := startGearman(t)
	go func() { _, _ = client.Write([]byte(strings.Repeat("A", maxGearmanLine+10))) }()
	frames := waitGearmanEvent(t, hp, done)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Len(t, frames[0].Payload, maxGearmanLine)
}
