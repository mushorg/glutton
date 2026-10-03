package tcp

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestStripTelnetIAC(t *testing.T) {
	iac := []byte{0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd, 0x23, 0xff, 0xfd, 0x27}
	cleaned, negotiation := stripTelnetIAC(append(append([]byte{}, iac...), []byte("root\r\n")...))
	require.Equal(t, iac, negotiation)
	require.Equal(t, []byte("root\r\n"), cleaned)

	cleaned, negotiation = stripTelnetIAC([]byte{0xff, 0xff, 'x'})
	require.Empty(t, negotiation)
	require.Equal(t, []byte{0xff, 'x'}, cleaned)
}

func TestHandleTelnetMiraiFlow(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleTelnet(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	expect := func(want string) {
		t.Helper()
		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, len(want))
		_, err := io.ReadFull(reader, buf)
		require.NoError(t, err)
		require.Equal(t, want, string(buf))
	}
	send := func(data string) {
		t.Helper()
		require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err := client.Write([]byte(data))
		require.NoError(t, err)
	}

	negotiate := "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"
	expect(negotiate)
	expect("Username: ")
	// Mirai replies with IAC negotiation then the username on the same line.
	send(negotiate + "root\r\n")
	expect("Password: ")
	send("juantech\r\n")
	expect("welcome\r\n> ")

	send("enable\x00\r\n")
	expect("-bash: enable: command not found\r\n")
	expect("> ")

	send("linuxshell\x00\r\n")
	expect("> ")

	send("system\x00\r\n")
	expect("-bash: system: command not found\r\n")
	expect("> ")

	send("shell\x00\r\n")
	expect("-bash: shell: command not found\r\n")
	expect("> ")

	send("sh\x00\r\n")
	expect("$\r\n")
	expect("> ")

	send("/bin/busybox UNSTABLE\x00\r\n")
	expect("UNSTABLE: applet not found\r\n")
	expect(busyboxBanner)
	expect("> ")

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "telnet", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedTelnet)
	require.True(t, ok, "decoded should be []parsedTelnet")

	want := []parsedTelnet{
		{Direction: "write", Message: negotiate},
		{Direction: "write", Message: "Username: "},
		{Direction: "read", Message: negotiate},
		{Direction: "read", Message: "root\r\n"},
		{Direction: "write", Message: "Password: "},
		{Direction: "read", Message: "juantech\r\n"},
		{Direction: "write", Message: "welcome\r\n> "},
		{Direction: "read", Message: "enable\x00\r\n"},
		{Direction: "write", Message: "-bash: enable: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Message: "linuxshell\x00\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Message: "system\x00\r\n"},
		{Direction: "write", Message: "-bash: system: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Message: "shell\x00\r\n"},
		{Direction: "write", Message: "-bash: shell: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Message: "sh\x00\r\n"},
		{Direction: "write", Message: "$\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Message: "/bin/busybox UNSTABLE\x00\r\n"},
		{Direction: "write", Message: "UNSTABLE: applet not found\r\n"},
		{Direction: "write", Message: busyboxBanner},
		{Direction: "write", Message: "> "},
	}
	require.Equal(t, want, events)
}

func TestHandleTelnetClientDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleTelnet(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	negotiate := make([]byte, 12)
	_, err := io.ReadFull(reader, negotiate)
	require.NoError(t, err)
	userPrompt := make([]byte, len("Username: "))
	_, err = io.ReadFull(reader, userPrompt)
	require.NoError(t, err)
	require.Equal(t, "Username: ", string(userPrompt))

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "telnet", produced.protocol)
	events, ok := produced.decoded.([]parsedTelnet)
	require.True(t, ok)
	require.Equal(t, []parsedTelnet{
		{Direction: "write", Message: string(negotiate)},
		{Direction: "write", Message: "Username: "},
	}, events)
}
