package tcp

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/mushorg/glutton/producer"
	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"

	cryptossh "golang.org/x/crypto/ssh"
)

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

// serveShell serves the session channels of a logged-in client with the fake
// shell and returns when the client is gone or the first session has ended.
func (s *sshServer) serveShell(sconn *cryptossh.ServerConn, chans <-chan cryptossh.NewChannel, reqs <-chan *cryptossh.Request) {
	go cryptossh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	sessions := 0
	for nc := range chans {
		if nc.ChannelType() != "session" {
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(ch, creqs, sshproto.NewShell(s.persona, sconn.User()))
			// the visit is over once the shell is; a real sshd would wait
			// for the client, which a bot may never do
			_ = sconn.Close()
		}()
	}
	wg.Wait()
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
				ok = false
			}
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}()

	st, ok := <-start
	if !ok {
		return
	}
	if st.isExec {
		res := sh.Run(st.exec)
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
	status := uint32(0)
	if res.Status == sshproto.StatusNotFound {
		status = 127
	}
	_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{status}))
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
