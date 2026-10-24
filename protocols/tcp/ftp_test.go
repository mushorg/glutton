package tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
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
		{Direction: "read", Command: "USER", Username: "anonymous", Payload: []byte("USER anonymous\r\n")},
		{Direction: "write", Status: "331", Payload: []byte("331 Ok.\r\n")},
		{Direction: "read", Command: "PASS", Password: "ftp", Payload: []byte("PASS ftp\r\n")},
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

func TestHandleFTPPipelinedAndLongLines(t *testing.T) {
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
	send := func(data string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err := client.Write([]byte(data))
		require.NoError(t, err)
	}

	expect("220 Welcome")
	// both commands in one write: the second must not be lost with the first read's buffer
	go send("USER anonymous\r\nPASS " + strings.Repeat("p", maxFTPLine) + "\r\nQUIT\r\n")
	expect("331 Ok.")
	expect("230 Ok.")
	expect("221 Goodbye.")
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	events := waitProduced(t, hp).decoded.([]parsedFTP)
	require.Len(t, events, 7)
	pass := events[3]
	require.Equal(t, "PASS", pass.Command)
	require.True(t, pass.Truncated)
	require.Len(t, pass.Payload, maxFTPLine)
	require.Equal(t, "QUIT", events[5].Command)
	require.False(t, events[5].Truncated)
}

func TestHandleFTPEndsAtFrameLimit(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleFTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	go func() {
		for i := 0; i < maxFTPFrames; i++ {
			if _, err := client.Write([]byte("NOOP\r\n")); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	// the greeting plus read/write pairs: the cap is checked between commands
	n := len(produced.decoded.([]parsedFTP))
	require.GreaterOrEqual(t, n, maxFTPFrames)
	require.LessOrEqual(t, n, maxFTPFrames+1)
}

func startFTP(t *testing.T) (send func(string), expect func(string), hp *fakeHoneypot, done chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp = newFakeHoneypot()
	done = make(chan error, 1)
	go func() {
		done <- HandleFTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	reader := bufio.NewReader(client)
	expect = func(want string) {
		t.Helper()
		require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, want+"\r\n", line)
	}
	send = func(line string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(3*time.Second)))
		_, err := client.Write([]byte(line + "\r\n"))
		require.NoError(t, err)
	}
	expect("220 Welcome")
	return send, expect, hp, done
}

// STOR before any PORT used to index an empty PORT argument and panic.
func TestHandleFTPStorWithoutPort(t *testing.T) {
	send, expect, hp, done := startFTP(t)
	send("STOR x.sh")
	expect("425 Use PORT or PASV first.")
	send("PORT 1,2,3")
	expect("501 Illegal PORT command.")
	send("PORT 1,2,3,4,999,1")
	expect("501 Illegal PORT command.")
	send("STOR x.sh")
	expect("425 Use PORT or PASV first.")
	send("QUIT")
	expect("221 Goodbye.")
	require.NoError(t, <-done)
	require.Equal(t, connection.EndHandlerClose, waitProduced(t, hp).endReason)
}

func TestHandleFTPStorStoresReceivedBytes(t *testing.T) {
	t.Chdir(t.TempDir()) // helpers.Store writes ./payloads
	upload := []byte("#!/bin/sh\necho pwned\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(upload)
		_ = c.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	send, expect, hp, done := startFTP(t)
	send(fmt.Sprintf("PORT 127,0,0,1,%d,%d", port>>8, port&0xff))
	expect("200 PORT command successful.")
	send("STOR x.sh")
	expect("150 Ok to send data.")
	expect("226 File received.")
	send("QUIT")
	expect("221 Goodbye.")
	require.NoError(t, <-done)

	sum := sha256.Sum256(upload)
	var stored *parsedFTP
	events := waitProduced(t, hp).decoded.([]parsedFTP)
	for i := range events {
		if events[i].PayloadHash != "" {
			stored = &events[i]
		}
	}
	require.NotNil(t, stored)
	require.Equal(t, upload, stored.Payload)
	require.Equal(t, hex.EncodeToString(sum[:]), stored.PayloadHash)
	require.FileExists(t, filepath.Join("payloads", "ftp", stored.PayloadHash))
}

func TestParseFTPPort(t *testing.T) {
	addr, err := parseFTPPort("10,0,0,1,4,1")
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1:1025", addr)
	for _, bad := range []string{"", "1,2,3,4,5", "1,2,3,4,5,6,7", "a,2,3,4,5,6", "1,2,3,4,256,0", "1,2,3,-1,5,6"} {
		_, err := parseFTPPort(bad)
		require.Error(t, err, bad)
	}
}
