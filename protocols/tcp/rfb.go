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

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rfb"
)

const (
	rfbMaxFrames   = 256     // frames per session; pointer events add up fast
	rfbMaxPayload  = 4096    // bytes kept per frame; the rest is discarded
	rfbMaxBody     = 1 << 20 // larger announced bodies end the session
	rfbDesktopName = "rfb-go"
	rfbWidth       = 1024
	rfbHeight      = 768
)

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
	events  []parsedRFB
	conn    net.Conn
	reader  *bufio.Reader
	rand    io.Reader
	version rfb.Version
}

func newRFBServer(conn net.Conn) *rfbServer {
	return &rfbServer{events: []parsedRFB{}, conn: conn, reader: bufio.NewReader(conn), rand: rand.Reader}
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
		case rfb.MsgKeyEvent:
			if down, sym := rfb.KeyEvent(header); down {
				frame.Key = rfb.KeysymName(sym)
			}
		case rfb.MsgSetEncodings:
			frame.Encodings = rfb.Encodings(body)
		case rfb.MsgClientCutText:
			frame.Text = string(body)
		}
		s.record(frame)
		if err != nil {
			return readEnd(err), nil
		}
	}
	return connection.EndMaxFrames, nil
}
