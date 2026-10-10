package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rtsp"
)

const (
	// rtspMaxBody caps the stored request body (ANNOUNCE SDP, SET_PARAMETER).
	rtspMaxBody = 64 * 1024
	// rtspMaxRequests bounds the frames recorded for one connection.
	rtspMaxRequests = 100
)

type parsedRTSP struct {
	Direction      string `json:"direction,omitempty"`
	Command        string `json:"command,omitempty"` // request method
	Path           string `json:"path,omitempty"`    // request URI path
	Status         string `json:"status,omitempty"`  // response code on writes
	CSeq           string `json:"cseq,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	AuthScheme     string `json:"auth_scheme,omitempty"` // basic, digest, or uri (credentials in the URI)
	Username       string `json:"username,omitempty"`
	DigestResponse string `json:"digest_response,omitempty"`
	Payload        []byte `json:"payload,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
}

// rtspRealm is the camera's realm, stable for the life of the sensor process.
var rtspRealm = sync.OnceValue(func() string { return "Login to " + rtsp.RandomSerial() })

// newRTSPResponder builds the per-session responder; tests swap it for a
// fixed nonce and clock.
var newRTSPResponder = func() *rtsp.Responder { return rtsp.NewResponder(rtspRealm()) }

type rtspServer struct {
	events    []parsedRTSP
	conn      net.Conn
	reader    *bufio.Reader
	responder *rtsp.Responder
}

func (s *rtspServer) read() (rtsp.Request, error) {
	req, raw, truncated, err := rtsp.ReadRequest(s.reader, rtspMaxBody)
	if len(raw) == 0 {
		return req, err
	}
	frame := parsedRTSP{
		Direction: "read",
		Command:   req.Method,
		CSeq:      req.Header("CSeq"),
		UserAgent: req.Header("User-Agent"),
		Payload:   raw,
		Truncated: truncated,
	}
	if req.URI != "" {
		frame.Path = req.Path()
	}
	if value := req.Header("Authorization"); value != "" {
		auth := rtsp.ParseAuthorization(value)
		frame.AuthScheme, frame.Username, frame.DigestResponse = auth.Scheme, auth.Username, auth.Response
	} else if user := req.URIUsername(); user != "" {
		frame.AuthScheme, frame.Username = "uri", user
	}
	s.events = append(s.events, frame)
	return req, err
}

func (s *rtspServer) write(req rtsp.Request) error {
	code, data := s.responder.Reply(req)
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame := parsedRTSP{Direction: "write", Status: strconv.Itoa(code), Payload: data}
	if code != 400 {
		frame.CSeq = req.Header("CSeq")
	}
	s.events = append(s.events, frame)
	return nil
}

// HandleRTSP takes a net.Conn and answers RTSP/1.0 like an IP camera that
// wants credentials: OPTIONS succeeds, every stream request gets a 401.
func HandleRTSP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rtspServer{events: []parsedRTSP{}, conn: conn, reader: bufio.NewReader(conn), responder: newRTSPResponder()}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rtsp", conn, md, helpers.FirstOrEmpty[parsedRTSP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RTSP connection", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < rtspMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			if errors.Is(err, rtsp.ErrMalformed) || errors.Is(err, rtsp.ErrLineTooLong) || errors.Is(err, rtsp.ErrBodyTooLarge) {
				logger.Debug("Malformed RTSP request", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("RTSP request received",
				slog.String("handler", "rtsp"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("method", req.Method),
				slog.String("path", req.Path()),
			)
		}
		if err := server.write(req); err != nil {
			logger.Error("Failed to write RTSP response", slog.String("protocol", "rtsp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
