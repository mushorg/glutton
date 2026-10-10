package tcp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/adb"
)

// The transport emulation (connect, shell, push) follows the behavior of
// bontchev/adbhoneypot (https://gitlab.com/bontchev/adbhoneypot); no code is
// taken from it. Wire formats come from AOSP's protocol.txt and SYNC.TXT.

const (
	maxADBMessages = 4096
	maxADBStreams  = 16
	// maxADBCapture bounds the raw bytes kept in decoded payloads per session.
	maxADBCapture  = 64 * 1024
	maxADBFileSize = 8 * 1024 * 1024
	maxADBLine     = 4096

	// The persona is an Android 6 TV box with ADB over TCP and auth disabled,
	// so it answers CNXN directly and speaks the v1 protocol.
	adbVersion = 0x01000000
	adbMaxData = 4096
	adbMtime   = 1546300800
	adbDirMode = 0o40771
)

var (
	adbIdentity = "device::ro.product.name=p281;ro.product.model=MBOX;ro.product.device=p281;\x00"
	adbPrompt   = "shell@p281:/ $ "
	adbDirs     = map[string]bool{
		"/": true, "/data": true, "/data/local": true, "/data/local/tmp": true,
		"/sdcard": true, "/sdcard/Download": true, "/system": true, "/system/bin": true, "/dev": true,
	}
	adbShell = map[string]string{
		"id":                               "uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:shell:s0\n",
		"whoami":                           "shell\n",
		"uname -m":                         "armv7l\n",
		"getprop ro.product.model":         "MBOX\n",
		"getprop ro.product.name":          "p281\n",
		"getprop ro.product.device":        "p281\n",
		"getprop ro.product.cpu.abi":       "armeabi-v7a\n",
		"getprop ro.build.version.release": "6.0.1\n",
	}
	adbStore = helpers.Store
)

type parsedADB struct {
	Direction   string   `json:"direction,omitempty"`
	Packet      string   `json:"packet,omitempty"`
	Command     string   `json:"command,omitempty"`
	Args        string   `json:"args,omitempty"`
	Path        string   `json:"path,omitempty"`
	Status      string   `json:"status,omitempty"`
	Identity    string   `json:"identity,omitempty"`
	AuthType    string   `json:"auth_type,omitempty"`
	Sync        []string `json:"sync,omitempty"`
	PayloadHash string   `json:"payload_hash,omitempty"`
	Size        int      `json:"size,omitempty"`
	Payload     []byte   `json:"payload,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
}

type adbFile struct {
	path      string
	data      []byte
	size      int
	truncated bool
}

type adbStream struct {
	remote      uint32 // the client's id for the stream
	service     string
	interactive bool
	line        []byte
	sync        *adb.SyncParser
	file        *adbFile
	frame       int // read frame collecting this stream's sync DATA, -1 for none
}

type adbServer struct {
	events    []parsedADB
	conn      net.Conn
	reader    *bufio.Reader
	logger    interfaces.Logger
	connected bool
	nextID    uint32
	streams   map[uint32]*adbStream
	captured  int
}

// capture copies raw for a decoded payload within the session budget.
func (s *adbServer) capture(raw []byte) ([]byte, bool) {
	room := maxADBCapture - s.captured
	if room <= 0 {
		return nil, len(raw) > 0
	}
	if len(raw) > room {
		s.captured += room
		return bytes.Clone(raw[:room]), true
	}
	s.captured += len(raw)
	return bytes.Clone(raw), false
}

func (s *adbServer) record(frame parsedADB, raw []byte) int {
	frame.Direction = "read"
	frame.Payload, frame.Truncated = s.capture(raw)
	s.events = append(s.events, frame)
	return len(s.events) - 1
}

// send writes a transport message and records it as a write frame unless
// frame is nil (WRTE acknowledgements are flow control and not recorded).
func (s *adbServer) send(frame *parsedADB, cmd, arg0, arg1 uint32, data []byte) error {
	msg := adb.Build(cmd, arg0, arg1, data)
	if _, err := s.conn.Write(msg); err != nil {
		return err
	}
	if frame != nil {
		frame.Direction = "write"
		frame.Packet = adb.CommandName(cmd)
		frame.Payload, frame.Truncated = s.capture(msg)
		s.events = append(s.events, *frame)
	}
	return nil
}

func (s *adbServer) handle(msg adb.Message, raw []byte) error {
	frame := parsedADB{Packet: msg.Name(), Command: msg.Name()}
	switch msg.Command {
	case adb.CmdCNXN:
		frame.Identity = adb.SystemIdentity(msg.Data)
		s.record(frame, raw)
		s.connected = true
		return s.send(&parsedADB{Command: "CNXN", Identity: adb.SystemIdentity([]byte(adbIdentity))},
			adb.CmdCNXN, adbVersion, adbMaxData, []byte(adbIdentity))
	case adb.CmdAUTH:
		// the device never asks for auth, so an AUTH is only recorded
		frame.AuthType = adb.AuthTypeName(msg.Arg0)
		s.record(frame, raw)
		return nil
	case adb.CmdOPEN:
		frame.Command, frame.Args = adb.SplitService(msg.Data)
		s.record(frame, raw)
		s.logger.Info("ADB open",
			slog.String("handler", "adb"),
			slog.String("protocol", "adb"),
			slog.String("service", frame.Command),
			slog.String("args", frame.Args),
		)
		return s.open(msg.Arg0, frame.Command, frame.Args)
	case adb.CmdWRTE:
		return s.wrte(msg, raw, frame)
	case adb.CmdCLSE:
		delete(s.streams, msg.Arg1)
	}
	s.record(frame, raw)
	return nil
}

func (s *adbServer) open(remote uint32, service, arg string) error {
	// an offline device ignores OPEN; remote id 0 is invalid
	if !s.connected || remote == 0 {
		return nil
	}
	if len(s.streams) >= maxADBStreams || (service != "shell" && service != "exec" && service != "sync") {
		// never forward tcp:, localabstract:, reverse:, ...: refuse like a failed service
		return s.send(&parsedADB{Command: service, Status: "rejected"}, adb.CmdCLSE, 0, remote, nil)
	}
	local := s.nextID
	s.nextID++
	stream := &adbStream{remote: remote, service: service, frame: -1}
	s.streams[local] = stream
	if err := s.send(&parsedADB{Command: service, Status: "accepted"}, adb.CmdOKAY, local, remote, nil); err != nil {
		return err
	}
	switch {
	case service == "sync":
		stream.sync = &adb.SyncParser{}
		return nil
	case service == "shell" && arg == "":
		stream.interactive = true
		return s.send(&parsedADB{Command: service}, adb.CmdWRTE, local, remote, []byte(adbPrompt))
	}
	if out := adbShellOutput(arg); out != "" {
		if err := s.send(&parsedADB{Command: service}, adb.CmdWRTE, local, remote, []byte(out)); err != nil {
			return err
		}
	}
	return s.closeStream(local)
}

func (s *adbServer) closeStream(local uint32) error {
	stream := s.streams[local]
	delete(s.streams, local)
	return s.send(&parsedADB{Command: stream.service}, adb.CmdCLSE, local, stream.remote, nil)
}

func (s *adbServer) wrte(msg adb.Message, raw []byte, frame parsedADB) error {
	local := msg.Arg1
	stream, ok := s.streams[local]
	if !ok || stream.remote != msg.Arg0 {
		s.record(frame, raw)
		return nil
	}
	frame.Command = stream.service
	if err := s.send(nil, adb.CmdOKAY, local, stream.remote, nil); err != nil {
		return err
	}
	if stream.sync != nil {
		return s.syncInput(local, stream, msg.Data, raw, frame)
	}
	frame.Args = strings.TrimRight(string(msg.Data), "\r\n\x00")
	s.record(frame, raw)
	if !stream.interactive {
		return nil
	}
	stream.line = append(stream.line, msg.Data...)
	var out strings.Builder
	for {
		var cmd string
		if i := bytes.IndexAny(stream.line, "\r\n"); i >= 0 {
			cmd = string(stream.line[:i])
			stream.line = stream.line[i+1:]
		} else if len(stream.line) >= maxADBLine {
			// an overlong line without a newline runs as is
			cmd = string(stream.line)
			stream.line = nil
		} else {
			break
		}
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		if cmd == "exit" {
			return s.closeStream(local)
		}
		out.WriteString(adbShellOutput(cmd))
		out.WriteString(adbPrompt)
	}
	if out.Len() == 0 {
		return nil
	}
	return s.send(&parsedADB{Command: stream.service}, adb.CmdWRTE, local, stream.remote, []byte(out.String()))
}

func (s *adbServer) syncInput(local uint32, stream *adbStream, data, raw []byte, frame parsedADB) error {
	reqs, perr := stream.sync.Feed(data)
	onlyData := perr == nil
	for _, r := range reqs {
		if r.ID != "DATA" {
			onlyData = false
		}
	}
	// a pushed file spans many WRTEs: aggregate its DATA into one frame
	var idx int
	if onlyData && stream.file != nil && stream.frame >= 0 {
		idx = stream.frame
		p, truncated := s.capture(raw)
		s.events[idx].Payload = append(s.events[idx].Payload, p...)
		s.events[idx].Truncated = s.events[idx].Truncated || truncated
	} else {
		frame.Command = "sync"
		idx = s.record(frame, raw)
		stream.frame = idx
	}
	for _, r := range reqs {
		if r.ID != "DATA" || len(s.events[idx].Sync) == 0 || s.events[idx].Sync[len(s.events[idx].Sync)-1] != "DATA" {
			s.events[idx].Sync = append(s.events[idx].Sync, r.ID)
		}
		reply := &parsedADB{Command: "sync", Path: r.Path}
		var out []byte
		switch r.ID {
		case "SEND":
			stream.file = &adbFile{path: r.Path}
			s.events[idx].Path = r.Path
			continue
		case "DATA":
			if f := stream.file; f != nil {
				f.size += len(r.Data)
				room := maxADBFileSize - len(f.data)
				if len(r.Data) > room {
					f.truncated = true
					r.Data = r.Data[:max(room, 0)]
				}
				f.data = append(f.data, r.Data...)
			}
			continue
		case "DONE":
			f := stream.file
			if f == nil {
				out = adb.SyncFail("protocol failure")
				break
			}
			stream.file = nil
			idx = s.storeFile(idx, f)
			stream.frame = -1
			reply.Path = f.path
			out = adb.SyncOkay()
		case "STAT":
			s.events[idx].Path = r.Path
			if adbDirs[path.Clean(r.Path)] {
				out = adb.SyncStat(adbDirMode, 4096, adbMtime)
			} else {
				out = adb.SyncStat(0, 0, 0)
			}
		case "LIST":
			s.events[idx].Path = r.Path
			out = adb.SyncListDone()
		case "RECV":
			s.events[idx].Path = r.Path
			out = adb.SyncFail("No such file or directory")
		case "QUIT":
			return s.closeStream(local)
		}
		reply.Status = string(out[:4])
		if err := s.send(reply, adb.CmdWRTE, local, stream.remote, out); err != nil {
			return err
		}
	}
	if perr != nil {
		s.logger.Debug("Invalid sync request", slog.String("protocol", "adb"), producer.ErrAttr(perr))
		if err := s.send(&parsedADB{Command: "sync", Status: "FAIL"}, adb.CmdWRTE, local, stream.remote, adb.SyncFail(perr.Error())); err != nil {
			return err
		}
		return s.closeStream(local)
	}
	return nil
}

// storeFile saves a pushed file and annotates the read frame at idx, or a
// new frame when idx already holds a file. It returns the annotated index.
func (s *adbServer) storeFile(idx int, f *adbFile) int {
	if s.events[idx].PayloadHash != "" {
		s.events = append(s.events, parsedADB{Direction: "read", Command: "sync", Sync: []string{"DONE"}})
		idx = len(s.events) - 1
	}
	e := &s.events[idx]
	e.Path = f.path
	e.Size = f.size
	e.Truncated = e.Truncated || f.truncated
	hash, err := adbStore(f.data, filepath.Join("payloads", "adb"))
	if err != nil {
		s.logger.Error("Failed to store ADB push", slog.String("protocol", "adb"), producer.ErrAttr(err))
		return idx
	}
	e.PayloadHash = hash
	s.logger.Info("ADB push stored",
		slog.String("handler", "adb"),
		slog.String("protocol", "adb"),
		slog.String("path", f.path),
		slog.String("sha256", hash),
	)
	return idx
}

// adbShellOutput returns canned output for common recon commands. Everything
// else, including download-and-run chains, succeeds silently.
func adbShellOutput(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if out, ok := adbShell[cmd]; ok {
		return out
	}
	if arg, ok := strings.CutPrefix(cmd, "echo "); ok && !strings.ContainsAny(arg, ";|&$`<>()\\") {
		return strings.Trim(arg, `"'`) + "\n"
	}
	return ""
}

// readHexLength reads the next 4 bytes from r as an ASCII hex-encoded length and parses them into an int.
func readHexLength(r io.Reader) (int, error) {
	lengthHex := make([]byte, 4)
	_, err := io.ReadFull(r, lengthHex)
	if err != nil {
		return 0, err
	}

	length, err := strconv.ParseInt(string(lengthHex), 16, 64)
	if err != nil {
		return 0, err
	}
	// Clip the length to 255, as per the Google implementation.
	if length > 255 {
		length = 255
	}

	return int(length), nil
}

func adbCommand(data []byte) string {
	s := string(data)
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i]
	}
	if i := strings.IndexByte(s, '\x00'); i > 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

// hostRequest reads one host smart-socket request ("000chost:version"), the
// framing adb clients use towards the adb server on tcp/5037.
func (s *adbServer) hostRequest() (string, error) {
	length, err := readHexLength(s.reader)
	if err != nil {
		return connection.EndReasonFromRead(err), err
	}
	data := make([]byte, length)
	n, err := io.ReadFull(s.reader, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return connection.EndReasonFromRead(err), fmt.Errorf("error reading message data: %w", err)
	} else if err == io.ErrUnexpectedEOF {
		return connection.EndReasonFromRead(err), fmt.Errorf("incomplete message data: got %d, want %d. Error: %w", n, length, err)
	}

	s.events = append(s.events, parsedADB{
		Direction: "read",
		Command:   adbCommand(data[:n]),
		Payload:   data[:n],
		Truncated: length == 255,
	})

	s.logger.Info("handled adb request", slog.String("protocol", "adb"), slog.Int("data_read", n))
	return connection.EndHandlerClose, nil
}

// HandleADB Android Debug bridge handler
func HandleADB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &adbServer{
		events:  []parsedADB{},
		conn:    conn,
		reader:  bufio.NewReader(conn),
		logger:  logger,
		nextID:  1,
		streams: map[uint32]*adbStream{},
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("adb", conn, md, helpers.FirstOrEmpty[parsedADB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "adb"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close ADB connection", slog.String("protocol", "adb"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "adb"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	prefix, err := server.reader.Peek(4)
	if err != nil {
		logger.Debug("Failed to read data", slog.String("protocol", "adb"), producer.ErrAttr(err))
		if len(prefix) > 0 {
			server.record(parsedADB{}, prefix)
		}
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	if adb.IsHexLength(prefix) {
		endReason, err = server.hostRequest()
		return err
	}

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	logger.Info("ADB connection",
		slog.String("handler", "adb"),
		slog.String("protocol", "adb"),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
	)

	for i := 0; i < maxADBMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "adb"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		msg, raw, err := adb.ReadMessage(server.reader, adb.MaxPayload)
		if err != nil {
			if len(raw) > 0 {
				frame := parsedADB{}
				if len(raw) >= adb.HeaderLen {
					frame.Packet, frame.Command = msg.Name(), msg.Name()
				}
				idx := server.record(frame, raw)
				if errors.Is(err, adb.ErrTooLarge) {
					server.events[idx].Truncated = true
				}
			}
			if errors.Is(err, adb.ErrBadMagic) || errors.Is(err, adb.ErrTooLarge) {
				logger.Debug("Invalid ADB message", slog.String("protocol", "adb"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return nil
			}
			if err != io.EOF {
				logger.Debug("Failed to read data", slog.String("protocol", "adb"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if err := server.handle(msg, raw); err != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "adb"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
