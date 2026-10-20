package tcp

import (
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"

	"github.com/spf13/viper"
	cryptossh "golang.org/x/crypto/ssh"
)

// sshMaxFramePayload caps the payload of a write-file, channel-open,
// channel-request or global-request frame; the stored file is complete.
const sshMaxFramePayload = 4096

// sshStore keeps the files the shell wrote; tests replace it.
var sshStore = helpers.Store

// addFrame appends a post-authentication frame; the plaintext of the session
// is recorded as the shell sees it.
func (s *sshServer) addFrame(f parsedSSH) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced {
		return
	}
	s.events = append(s.events, f)
}

// addExtra appends a frame that a client can repeat at will, up to
// sshMaxExtraFrames per connection, and caps its payload.
func (s *sshServer) addExtra(f parsedSSH) {
	if len(f.Payload) > sshMaxFramePayload {
		f.Payload, f.Truncated = f.Payload[:sshMaxFramePayload], true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced || s.extra >= sshMaxExtraFrames {
		return
	}
	s.extra++
	s.events = append(s.events, f)
}

// recordWrites records the files a shell line wrote and stores their content.
func (s *sshServer) recordWrites(writes []sshproto.FileWrite) {
	for _, w := range writes {
		f := parsedSSH{Direction: "read", Command: "write-file", Path: w.Path, Payload: w.Data}
		hash, err := sshStore(w.Data, filepath.Join("payloads", "ssh"))
		if err != nil {
			s.logger.Debug("Failed to store SSH file", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		} else {
			f.PayloadHash = hash
		}
		s.addExtra(f)
	}
}

// sshIdle closes a logged-in connection that has no running session for the
// idle timeout, or as soon as its last allowed session ends.
type sshIdle struct {
	mu     sync.Mutex
	active int
	d      time.Duration
	timer  *time.Timer
	close  func()
}

func newSSHIdle(d time.Duration, closeFn func()) *sshIdle {
	return &sshIdle{d: d, close: closeFn, timer: time.AfterFunc(d, closeFn)}
}

// touch restarts the countdown when something other than a session happened.
func (i *sshIdle) touch() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.active == 0 {
		i.timer.Reset(i.d)
	}
}

func (i *sshIdle) begin() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.active++
	i.timer.Stop()
}

// end reports a finished session; final is set when no more may start.
func (i *sshIdle) end(final bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.active--; i.active > 0 {
		return
	}
	if final {
		go i.close()
		return
	}
	i.timer.Reset(i.d)
}

func (i *sshIdle) stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timer.Stop()
}

func sshIdleDuration() time.Duration {
	if d := viper.GetDuration("ssh.idle_timeout"); d > 0 {
		return d
	}
	return sshIdleTimeout
}

// serveShell serves the session channels of a logged-in client with the fake
// shell. The connection stays open for up to sshMaxSessions sessions, as a
// real sshd's does, and closes when the client leaves, the last session ends,
// or nothing has run for the idle timeout. Other channel types and global
// requests are recorded and refused; nothing they name is dialed.
func (s *sshServer) serveShell(sconn *cryptossh.ServerConn, chans <-chan cryptossh.NewChannel, reqs <-chan *cryptossh.Request) {
	idle := newSSHIdle(sshIdleDuration(), func() { _ = sconn.Close() })
	defer idle.stop()
	go s.globalRequests(reqs, idle)
	var wg sync.WaitGroup
	shell := sshproto.NewShell(s.persona, sconn.User())
	sessions := 0
	for nc := range chans {
		idle.touch()
		if nc.ChannelType() != "session" {
			s.recordChannel(nc)
			_ = nc.Reject(cryptossh.UnknownChannelType, "unknown channel type")
			continue
		}
		if sessions >= sshMaxSessions {
			_ = nc.Reject(cryptossh.ResourceShortage, "too many sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			s.logger.Debug("Failed to accept SSH channel", slog.String("protocol", "ssh"), producer.ErrAttr(err))
			continue
		}
		sessions++
		final := sessions >= sshMaxSessions
		idle.begin()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(ch, creqs, shell.Session())
			idle.end(final)
		}()
	}
	wg.Wait()
}

// forward is the payload of direct-tcpip and forwarded-tcpip channel opens.
type sshForward struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

// recordChannel records a refused channel open.
func (s *sshServer) recordChannel(nc cryptossh.NewChannel) {
	f := parsedSSH{Direction: "read", Command: "channel-open", Type: nc.ChannelType(), Payload: nc.ExtraData()}
	switch f.Type {
	case "direct-tcpip", "forwarded-tcpip":
		var fw sshForward
		if cryptossh.Unmarshal(nc.ExtraData(), &fw) == nil {
			f.Target = net.JoinHostPort(fw.Host, strconv.Itoa(int(fw.Port)))
		}
	}
	s.addExtra(f)
}

// globalRequests records and refuses the connection-level requests.
func (s *sshServer) globalRequests(reqs <-chan *cryptossh.Request, idle *sshIdle) {
	for r := range reqs {
		idle.touch()
		f := parsedSSH{Direction: "read", Command: "global-request", Type: r.Type, Payload: r.Payload}
		switch r.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			var req struct {
				Addr string
				Port uint32
			}
			if cryptossh.Unmarshal(r.Payload, &req) == nil {
				f.Target = net.JoinHostPort(req.Addr, strconv.Itoa(int(req.Port)))
			}
		}
		s.addExtra(f)
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

type sshSessionStart struct {
	exec   string
	isExec bool
}

// session answers the channel requests of one session and runs its shell or
// exec command.
func (s *sshServer) session(ch cryptossh.Channel, reqs <-chan *cryptossh.Request, sh *sshproto.Shell) {
	defer ch.Close()
	var pty atomic.Bool
	start := make(chan sshSessionStart, 1)
	go func() {
		defer close(start)
		for r := range reqs {
			ok := true
			switch r.Type {
			case "pty-req":
				pty.Store(true)
				s.addFrame(parsedSSH{Direction: "read", Command: "pty-req", Payload: r.Payload})
			case "env", "window-change", "signal":
			case "shell":
				s.addFrame(parsedSSH{Direction: "read", Command: "shell"})
				select {
				case start <- sshSessionStart{}:
				default:
				}
			case "exec":
				var req struct{ Command string }
				if err := cryptossh.Unmarshal(r.Payload, &req); err != nil {
					ok = false
					break
				}
				s.addFrame(parsedSSH{Direction: "read", Command: "exec", Payload: []byte(req.Command)})
				select {
				case start <- sshSessionStart{exec: req.Command, isExec: true}:
				default:
				}
			default:
				// subsystem (sftp), x11-req, auth-agent-req@openssh.com, ...
				ok = false
				s.addExtra(parsedSSH{Direction: "read", Command: "channel-request", Type: r.Type, Payload: r.Payload})
			}
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}()

	// a session that asks for neither a shell nor a command does not hold the
	// connection beyond the idle timeout
	var st sshSessionStart
	select {
	case v, ok := <-start:
		if !ok {
			return
		}
		st = v
	case <-time.After(sshIdleDuration()):
		return
	}
	if st.isExec {
		res := sh.Run(st.exec)
		s.recordWrites(res.Writes)
		s.writeOutput(ch, sh, res, false)
		sendExitStatus(ch, res)
		return
	}
	s.interact(ch, sh, &pty)
}

// interact runs the interactive shell: prompt, read a line, answer it.
func (s *sshServer) interact(ch cryptossh.Channel, sh *sshproto.Shell, pty *atomic.Bool) {
	var editor sshproto.LineEditor
	if _, err := ch.Write([]byte(sh.Prompt())); err != nil {
		return
	}
	buf := make([]byte, 1024)
	lines := 0
	for {
		n, err := ch.Read(buf)
		for _, b := range buf[:n] {
			k := editor.Feed(b)
			if k.EOF {
				sendExitStatus(ch, sshproto.Result{Status: sshproto.StatusOK})
				return
			}
			if pty.Load() && len(k.Echo) > 0 {
				if _, werr := ch.Write(k.Echo); werr != nil {
					return
				}
			}
			if !k.Done {
				continue
			}
			if k.Line != "" {
				lines++
				s.addFrame(parsedSSH{Direction: "read", Command: "cmd", Payload: []byte(k.Line), Truncated: k.Truncated})
				res := sh.Run(k.Line)
				s.recordWrites(res.Writes)
				s.writeOutput(ch, sh, res, pty.Load())
				if res.Exit || lines >= sshMaxShellLines {
					sendExitStatus(ch, res)
					return
				}
			}
			if _, werr := ch.Write([]byte(sh.Prompt())); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// writeOutput sends the result of one line and records it.
func (s *sshServer) writeOutput(ch cryptossh.Channel, sh *sshproto.Shell, res sshproto.Result, pty bool) {
	out := res.Output
	if pty {
		out = crlf(out)
	}
	if out != "" {
		if _, err := ch.Write([]byte(out)); err != nil {
			s.logger.Debug("Failed to write SSH shell output", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		}
	}
	s.addFrame(parsedSSH{Direction: "write", Command: "cmd", Status: res.Status, Payload: []byte(res.Output)})
}

func sendExitStatus(ch cryptossh.Channel, res sshproto.Result) {
	_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{uint32(res.Code)}))
}

// crlf turns the shell's "\n" line ends into the "\r\n" a pty expects.
func crlf(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, s[i])
	}
	return string(out)
}
