package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/guard"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rfb"
)

const (
	rfbMaxFrames   = 256     // frames per session; pointer events add up fast
	rfbMaxPayload  = 4096    // bytes kept per frame; the rest is discarded
	rfbMaxBody     = 1 << 20 // larger announced bodies end the session
	rfbDesktopName = "ubuntu:1 (ubuntu)"
	rfbWidth       = 1024
	rfbHeight      = 768
)

// Updates have to get past tcp_reply_limit, which refuses any single write
// larger than the per-IP burst and anything beyond its refill rate. A full Raw
// screen at 32bpp is 3 MiB, so it is sent as bands of at most rfbMaxBandBytes,
// one per FramebufferUpdateRequest, written in rfbWriteChunk pieces and paced
// at three quarters of the default per-IP budget. A write refused anyway (a
// lower configured budget, parallel sessions from one IP) is retried every
// rfbLimitRetry for up to rfbLimitWait; a refusal costs no budget.
const (
	rfbMaxBandBytes = 512 << 10 // Raw pixel bytes per FramebufferUpdate
	rfbWriteChunk   = 64 << 10  // bytes per conn write
	rfbPaceBurst    = guard.DefaultTCPSourceBurst * 3 / 4
	rfbPaceRate     = guard.DefaultTCPSourceRate * 3 / 4 // bytes per second
	rfbLimitRetry   = time.Second
	rfbLimitWait    = 10 * time.Second
	// rfbMaxSessionBytes bounds update bytes per session: one full Raw
	// screen and some, about 70s of paced budget past the burst. Later requests go
	// unanswered.
	rfbMaxSessionBytes = 4 << 20
)

// rfbDesktop is the static screen: a desktop with a terminal window and a
// bottom panel.
var rfbDesktop = rfb.Scene{
	Width: rfbWidth, Height: rfbHeight,
	Background: rfb.Colour{R: 0x2c, G: 0x3e, B: 0x50},
	Fills: []rfb.Fill{
		{X: 160, Y: 120, Width: 640, Height: 400, Colour: rfb.Colour{R: 0x30, G: 0x0a, B: 0x24}},
		{X: 160, Y: 120, Width: 640, Height: 28, Colour: rfb.Colour{R: 0x3c, G: 0x3c, B: 0x3c}},
		{X: 0, Y: 736, Width: 1024, Height: 32, Colour: rfb.Colour{R: 0x1e, G: 0x1e, B: 0x1e}},
	},
}

// rfbDesktopRaw is the desktop in the default pixel format, rendered once and
// shared by all sessions.
var rfbDesktopRaw = sync.OnceValue(func() []byte {
	return rfb.RenderRaw(rfbDesktop, rfb.DefaultPixelFormat)
})

// rfbOffered is the 3.7+ security type list. VNC authentication accepts any
// password so brute-forcers reach the client message loop and reveal what they
// do next; None lets open-VNC scanners in the same way. The challenge/response
// pair is still captured before the session proceeds.
var rfbOffered = []uint8{rfb.SecurityVNCAuth, rfb.SecurityNone}

type parsedRFB struct {
	Direction    string  `json:"direction,omitempty"`
	Command      string  `json:"command,omitempty"`
	Status       string  `json:"status,omitempty"`
	Version      string  `json:"version,omitempty"`
	SecurityType string  `json:"security_type,omitempty"`
	Challenge    string  `json:"challenge,omitempty"`
	Response     string  `json:"response,omitempty"`
	Key          string  `json:"key,omitempty"`
	Text         string  `json:"text,omitempty"`
	Encodings    []int32 `json:"encodings,omitempty"`
	Payload      []byte  `json:"payload,omitempty"`
	Truncated    bool    `json:"truncated,omitempty"`
}

type rfbServer struct {
	events    []parsedRFB
	conn      net.Conn
	reader    *bufio.Reader
	rand      io.Reader
	version   rfb.Version
	pf        rfb.PixelFormat
	raw       []byte    // desktop rendered in pf, when pf is not the default
	encodings []int32   // from the client's last SetEncodings
	sent      int       // framebuffer update bytes written
	pending   *rfb.Rect // rest of a Raw request still to be sent, band by band

	// update pacing; now and sleep are swapped in tests
	paceRate, paceBurst float64
	tokens              float64
	paced               time.Time
	now                 func() time.Time
	sleep               func(time.Duration)
}

func newRFBServer(conn net.Conn) *rfbServer {
	return &rfbServer{
		events: []parsedRFB{}, conn: conn, reader: bufio.NewReader(conn), rand: rand.Reader, pf: rfb.DefaultPixelFormat,
		paceRate: rfbPaceRate, paceBurst: rfbPaceBurst, now: time.Now, sleep: time.Sleep,
	}
}

func (s *rfbServer) write(frame parsedRFB) error {
	if _, err := s.conn.Write(frame.Payload); err != nil {
		return err
	}
	frame.Direction = "write"
	s.events = append(s.events, frame)
	return nil
}

func (s *rfbServer) record(frame parsedRFB) {
	frame.Direction = "read"
	s.events = append(s.events, frame)
}

// pace waits until n more update bytes fit the pacing budget.
func (s *rfbServer) pace(n int) {
	now := s.now()
	if s.paced.IsZero() {
		s.tokens = s.paceBurst
	} else {
		s.tokens = min(s.paceBurst, s.tokens+now.Sub(s.paced).Seconds()*s.paceRate)
	}
	s.paced = now
	if need := float64(n) - s.tokens; need > 0 {
		s.sleep(time.Duration(need / s.paceRate * float64(time.Second)))
		s.tokens, s.paced = 0, s.now()
		return
	}
	s.tokens -= float64(n)
}

// writeChunk writes one paced chunk, retrying while the reply guard refuses
// it. It returns the bytes written.
func (s *rfbServer) writeChunk(chunk []byte) (int, error) {
	s.pace(len(chunk))
	for waited := time.Duration(0); ; waited += rfbLimitRetry {
		n, err := s.conn.Write(chunk)
		if !errors.Is(err, guard.ErrLimited) || waited >= rfbLimitWait {
			return n, err
		}
		s.sleep(rfbLimitRetry)
	}
}

// writeChunks writes head followed by data in writes of at most
// rfbWriteChunk bytes. It returns the bytes written.
func (s *rfbServer) writeChunks(head, data []byte) (int, error) {
	first := min(len(data), max(rfbWriteChunk-len(head), 0))
	chunk, rest := append(append([]byte(nil), head...), data[:first]...), data[first:]
	written := 0
	for {
		n, err := s.writeChunk(chunk)
		written += n
		if err != nil || len(rest) == 0 {
			return written, err
		}
		n = min(len(rest), rfbWriteChunk)
		chunk, rest = rest[:n], rest[n:]
	}
}

// writeUpdate sends a FramebufferUpdate given as header and pixel data and
// records it, keeping the first rfbMaxPayload bytes that reached the wire. A
// failed write is recorded with status "limited" (refused by the reply
// guard) or "write_error". sent is false when nothing was written; err is
// nil then if the guard refused the update, since the stream is still intact
// and the session can go on.
func (s *rfbServer) writeUpdate(frame parsedRFB, head, data []byte) (sent bool, err error) {
	wire, err := s.writeChunks(head, data)
	s.sent += wire
	frame.Direction = "write"
	keep := min(wire, rfbMaxPayload)
	frame.Payload = append(append([]byte(nil), head[:min(len(head), keep)]...), data[:max(keep-len(head), 0)]...)
	frame.Truncated = wire > keep || err != nil
	if err != nil {
		frame.Status = "write_error"
		if errors.Is(err, guard.ErrLimited) {
			frame.Status = "limited"
		}
	}
	s.events = append(s.events, frame)
	if wire == 0 && errors.Is(err, guard.ErrLimited) {
		return false, nil
	}
	return wire > 0, err
}

// update answers a FramebufferUpdateRequest with the desktop in the client's
// pixel format and preferred encoding. The screen never changes, so an
// incremental request is only answered while the client has not been sent a
// frame yet, as idle real servers do, or while bands of an earlier Raw
// request are still pending. A Raw rectangle over rfbMaxBandBytes is sent one
// band of rows per request, top first; a non-incremental request replaces
// what is pending. Requests that would exceed rfbMaxSessionBytes go
// unanswered.
func (s *rfbServer) update(req rfb.UpdateRequest) error {
	if !req.Incremental {
		s.pending = nil
	}
	var full rfb.Rect
	switch {
	case s.pending != nil:
		full = *s.pending
	case req.Incremental && s.sent > 0:
		return nil
	default:
		x, y, w, h, ok := rfb.ClampRect(req.X, req.Y, req.Width, req.Height, rfbWidth, rfbHeight)
		if !ok {
			head := rfb.FramebufferUpdateHeader(0)
			_, err := s.writeUpdate(parsedRFB{Command: "FramebufferUpdate"}, head, nil)
			return err
		}
		full = rfb.Rect{X: x, Y: y, Width: w, Height: h}
	}
	rect := full
	rect.Encoding = rfb.ChooseEncoding(s.encodings)
	var rest *rfb.Rect
	if rect.Encoding == rfb.EncodingRRE {
		rect.Data = rfb.RRE(rfbDesktop, s.pf, rect.X, rect.Y, rect.Width, rect.Height)
	} else {
		if rows := rfb.BandRows(rect.Width, s.pf, rfbMaxBandBytes); rows < rect.Height {
			rest = &rfb.Rect{X: rect.X, Y: rect.Y + rows, Width: rect.Width, Height: rect.Height - rows}
			rect.Height = rows
		}
		rect.Data = rfb.RawRect(s.desktopRaw(), s.pf, rfbWidth, rect.X, rect.Y, rect.Width, rect.Height)
	}
	head := append(rfb.FramebufferUpdateHeader(1), rect.Header()...)
	if s.sent+len(head)+len(rect.Data) > rfbMaxSessionBytes {
		return nil
	}
	// a band the guard refused is retried on the next request
	s.pending = &full
	sent, err := s.writeUpdate(parsedRFB{Command: "FramebufferUpdate", Encodings: []int32{rect.Encoding}}, head, rect.Data)
	if sent {
		s.pending = rest
	}
	return err
}

// desktopRaw returns the full desktop as Raw pixels in the client's format.
// The default format uses the shared buffer; others are rendered once per
// session.
func (s *rfbServer) desktopRaw() []byte {
	if s.pf == rfb.DefaultPixelFormat {
		return rfbDesktopRaw()
	}
	if s.raw == nil {
		s.raw = rfb.RenderRaw(rfbDesktop, s.pf)
	}
	return s.raw
}

// readN reads exactly n bytes. On a short read it returns what arrived; a
// client hanging up mid-message counts as a close, not a read error.
func (s *rfbServer) readN(n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := io.ReadFull(s.reader, buf)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return buf[:got], err
}

// readBody reads an n-byte message body, keeping at most rfbMaxPayload bytes.
func (s *rfbServer) readBody(n uint64) ([]byte, bool, error) {
	keep := min(n, rfbMaxPayload)
	body, err := s.readN(int(keep))
	if err != nil || keep == n {
		return body, false, err
	}
	if _, err := io.CopyN(io.Discard, s.reader, int64(n-keep)); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return body, true, err
	}
	return body, true, nil
}

// buffered returns client bytes that already arrived, for non-RFB input.
func (s *rfbServer) buffered() []byte {
	b, _ := s.reader.Peek(min(s.reader.Buffered(), rfbMaxPayload))
	return append([]byte(nil), b...)
}

func securityTypeNames(types []uint8) string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = rfb.SecurityTypeName(t)
	}
	return strings.Join(names, ",")
}

// HandleRFB takes a net.Conn and does basic RFB/VNC communication
func HandleRFB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleRFB(ctx, newRFBServer(conn), md, logger, h)
}

func handleRFB(ctx context.Context, server *rfbServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rfb", server.conn, md, helpers.FirstOrEmpty[parsedRFB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		}
		if err := server.conn.Close(); err != nil {
			logger.Debug("Failed to close RFB connection", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		}
	}()

	var err error
	endReason, err = server.serve(ctx, md, logger, h)
	return err
}

func (s *rfbServer) serve(ctx context.Context, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (string, error) {
	timeout := func() bool {
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rfb"), producer.ErrAttr(err))
			return false
		}
		return true
	}
	readEnd := func(err error) string {
		logger.Debug("Failed to read RFB", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		return connection.EndReasonFromRead(err)
	}

	if !timeout() {
		return connection.EndTimeout, nil
	}
	if err := s.write(parsedRFB{Command: "ProtocolVersion", Version: "3.8", Payload: rfb.ServerVersion}); err != nil {
		return connection.EndWriteError, err
	}

	if !timeout() {
		return connection.EndTimeout, nil
	}
	data, err := s.readN(rfb.VersionLen)
	version, ok := rfb.ParseVersion(data)
	frame := parsedRFB{Command: "ProtocolVersion", Payload: data}
	if ok {
		frame.Version = version.String()
	}
	if err != nil {
		if len(data) > 0 {
			s.record(frame)
		}
		return readEnd(err), nil
	}
	if !ok {
		// not an RFB client; keep whatever else it already sent
		frame.Command = ""
		frame.Payload = append(frame.Payload, s.buffered()...)
		s.record(frame)
		return connection.EndHandlerClose, nil
	}
	s.record(frame)
	s.version = version

	host, port, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	logger.Info(
		"rfb handshake",
		slog.String("handler", "rfb"),
		slog.String("protocol", "rfb"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("version", version.String()),
	)

	if s.version == rfb.Version33 {
		// 3.3 servers pick the security type themselves
		if err := s.write(parsedRFB{Command: "Security", SecurityType: rfb.SecurityTypeName(rfb.SecurityVNCAuth), Payload: rfb.SecurityType33(rfb.SecurityVNCAuth)}); err != nil {
			return connection.EndWriteError, err
		}
		return s.vncAuth(timeout, readEnd, logger)
	}

	if err := s.write(parsedRFB{Command: "Security", SecurityType: securityTypeNames(rfbOffered), Payload: rfb.SecurityTypes(rfbOffered...)}); err != nil {
		return connection.EndWriteError, err
	}
	if !timeout() {
		return connection.EndTimeout, nil
	}
	data, err = s.readN(1)
	if err != nil {
		return readEnd(err), nil
	}
	s.record(parsedRFB{Command: "SecurityType", SecurityType: rfb.SecurityTypeName(data[0]), Payload: data})

	switch data[0] {
	case rfb.SecurityVNCAuth:
		return s.vncAuth(timeout, readEnd, logger)
	case rfb.SecurityNone:
		// 3.7 skips SecurityResult for None
		if s.version == rfb.Version38 {
			if err := s.write(parsedRFB{Command: "SecurityResult", Status: "OK", Payload: rfb.SecurityResult(true, s.version, "")}); err != nil {
				return connection.EndWriteError, err
			}
		}
		return s.session(timeout, readEnd)
	}
	if s.version == rfb.Version38 {
		if err := s.write(parsedRFB{Command: "SecurityResult", Status: "Failed", Payload: rfb.SecurityResult(false, s.version, "Security type not supported")}); err != nil {
			return connection.EndWriteError, err
		}
	}
	return connection.EndHandlerClose, nil
}

// vncAuth sends a challenge, records the response and accepts any password so
// the client proceeds into the session.
func (s *rfbServer) vncAuth(timeout func() bool, readEnd func(error) string, logger interfaces.Logger) (string, error) {
	challenge := make([]byte, rfb.ChallengeLen)
	if _, err := io.ReadFull(s.rand, challenge); err != nil {
		logger.Error("Failed to generate VNC challenge", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		return connection.EndHandlerClose, err
	}
	if err := s.write(parsedRFB{Command: "VNCAuthChallenge", Challenge: hex.EncodeToString(challenge), Payload: challenge}); err != nil {
		return connection.EndWriteError, err
	}
	if !timeout() {
		return connection.EndTimeout, nil
	}
	data, err := s.readN(rfb.ChallengeLen)
	frame := parsedRFB{Command: "VNCAuthResponse", Payload: data}
	if len(data) == rfb.ChallengeLen {
		frame.Response = hex.EncodeToString(data)
	}
	if len(data) > 0 {
		s.record(frame)
	}
	if err != nil {
		return readEnd(err), nil
	}
	logger.Info("rfb auth attempt", slog.String("handler", "rfb"), slog.String("protocol", "rfb"), slog.String("response", frame.Response))
	if err := s.write(parsedRFB{Command: "SecurityResult", Status: "OK", Payload: rfb.SecurityResult(true, s.version, "")}); err != nil {
		return connection.EndWriteError, err
	}
	return s.session(timeout, readEnd)
}

// session runs the initialisation phase and records client messages.
func (s *rfbServer) session(timeout func() bool, readEnd func(error) string) (string, error) {
	if !timeout() {
		return connection.EndTimeout, nil
	}
	data, err := s.readN(1)
	if err != nil {
		return readEnd(err), nil
	}
	s.record(parsedRFB{Command: "ClientInit", Payload: data})
	if err := s.write(parsedRFB{Command: "ServerInit", Payload: rfb.ServerInit(rfbWidth, rfbHeight, rfb.DefaultPixelFormat, rfbDesktopName)}); err != nil {
		return connection.EndWriteError, err
	}

	for len(s.events) < rfbMaxFrames {
		if !timeout() {
			return connection.EndTimeout, nil
		}
		typ, err := s.readN(1)
		if err != nil {
			return readEnd(err), nil
		}
		headerLen, ok := rfb.ClientHeaderLen(typ[0])
		if !ok {
			s.record(parsedRFB{Payload: append(typ, s.buffered()...)})
			return connection.EndHandlerClose, nil
		}
		header, err := s.readN(headerLen)
		frame := parsedRFB{Command: rfb.ClientMessageName(typ[0]), Payload: append(typ, header...)}
		if err != nil {
			s.record(frame)
			return readEnd(err), nil
		}
		bodyLen := rfb.ClientBodyLen(typ[0], header)
		if bodyLen > rfbMaxBody {
			frame.Truncated = true
			s.record(frame)
			return connection.EndHandlerClose, nil
		}
		body, truncated, err := s.readBody(bodyLen)
		frame.Payload = append(frame.Payload, body...)
		frame.Truncated = truncated
		switch typ[0] {
		case rfb.MsgSetPixelFormat:
			// invalid formats are ignored and the current one kept
			if pf, ok := rfb.ParsePixelFormat(header); ok && pf != s.pf {
				s.pf, s.raw = pf, nil
			}
		case rfb.MsgKeyEvent:
			if down, sym := rfb.KeyEvent(header); down {
				frame.Key = rfb.KeysymName(sym)
			}
		case rfb.MsgSetEncodings:
			frame.Encodings = rfb.Encodings(body)
			s.encodings = frame.Encodings
		case rfb.MsgClientCutText:
			frame.Text = string(body)
		}
		s.record(frame)
		if err != nil {
			return readEnd(err), nil
		}
		if req, ok := rfb.ParseUpdateRequest(header); ok && typ[0] == rfb.MsgFramebufferUpdateRequest && len(s.events) < rfbMaxFrames {
			if err := s.update(req); err != nil {
				return connection.EndWriteError, err
			}
		}
	}
	return connection.EndMaxFrames, nil
}
