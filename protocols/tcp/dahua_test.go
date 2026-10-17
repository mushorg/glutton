package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/dahua"
	"github.com/stretchr/testify/require"
)

// login frame from Ochi event 31fde0ba-a47b-4817-9e9a-9ed5963786b0 (tcp/37777)
var dahuaCaptureLogin = []byte("\xa0\x00\x00\x60\x23\x00\x00\x00admin\x00\x00\x00159753\x00\x00\x04\x01\x00\x00\x00\x00\xa1\xaaadmin&&159753\x00Random:1792259910\r\n\r\n")

func startDahua(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleDahua(context.Background(), serverConn, connection.Metadata{TargetPort: 37777}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitDahua(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "dahua", produced.protocol)
	return produced, err
}

func TestHandleDahuaLogin(t *testing.T) {
	client, hp, done := startDahua(t)

	_, err := client.Write(dahuaCaptureLogin)
	require.NoError(t, err)
	reply := make([]byte, dahua.HeaderLen)
	_, err = client.Read(reply)
	require.NoError(t, err)
	require.Equal(t, dahua.BuildLoginResponse(dahua.StatusWrongPassword), reply)
	require.NoError(t, client.Close())

	produced, err := waitDahua(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, dahuaCaptureLogin, produced.payload)
	require.Equal(t, []parsedDahua{
		{Direction: "read", Command: "login", Username: "admin", Password: "159753", Nonce: "1792259910", Payload: dahuaCaptureLogin},
		{Direction: "write", Status: "login-denied", Payload: reply},
	}, produced.decoded)
}

func TestHandleDahuaUnknownCommandNoReply(t *testing.T) {
	client, hp, done := startDahua(t)

	frame := make([]byte, dahua.HeaderLen)
	frame[0] = 0xf1
	_, err := client.Write(frame)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitDahua(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedDahua{{Direction: "read", Command: "cmd-0xf1", Payload: frame}}, produced.decoded)
}

func TestHandleDahuaEarlyDisconnect(t *testing.T) {
	client, hp, done := startDahua(t)

	_, err := client.Write(dahuaCaptureLogin[:10])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitDahua(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedDahua{{Direction: "read", Payload: dahuaCaptureLogin[:10]}}, produced.decoded)
}

func TestHandleDahuaNoData(t *testing.T) {
	client, hp, done := startDahua(t)
	require.NoError(t, client.Close())

	produced, err := waitDahua(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
}
