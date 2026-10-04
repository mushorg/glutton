package tcp

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestHandleFTPLoginAndQuit(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleFTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	reader := bufio.NewReader(client)
	expect := func(want string) {
		t.Helper()
		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want+"\r\n", line)
	}
	send := func(line string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err := client.Write([]byte(line + "\r\n"))
		require.NoError(t, err)
	}

	expect("220 Welcome")
	send("USER anonymous")
	expect("331 Ok.")
	send("PASS ftp")
	expect("230 Ok.")
	send("QUIT")
	expect("221 Goodbye.")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "ftp", produced.protocol)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	events, ok := produced.decoded.([]parsedFTP)
	require.True(t, ok)
	require.Equal(t, []parsedFTP{
		{Direction: "write", Status: "220", Payload: []byte("220 Welcome\r\n")},
		{Direction: "read", Command: "USER", Payload: []byte("USER anonymous\r\n")},
		{Direction: "write", Status: "331", Payload: []byte("331 Ok.\r\n")},
		{Direction: "read", Command: "PASS", Payload: []byte("PASS ftp\r\n")},
		{Direction: "write", Status: "230", Payload: []byte("230 Ok.\r\n")},
		{Direction: "read", Command: "QUIT", Payload: []byte("QUIT\r\n")},
		{Direction: "write", Status: "221", Payload: []byte("221 Goodbye.\r\n")},
	}, events)
}

func TestHandleFTPClientDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleFTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "220 Welcome\r\n", string(buf[:n]))
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	events := produced.decoded.([]parsedFTP)
	require.Equal(t, "220", events[0].Status)
}
