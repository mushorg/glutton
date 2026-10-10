package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/icap"
	"github.com/spf13/viper"
)

const (
	// icapMaxBody caps the stored body of one REQMOD/RESPMOD request.
	icapMaxBody = 256 << 10
	// icapMaxRequests bounds the requests answered on one connection.
	icapMaxRequests = 100

	// The persona is the c-icap echo demo service, the stock c-icap install.
	defaultICAPServer  = "C-ICAP/0.5.10"
	defaultICAPService = "C-ICAP/0.5.10 server - Echo demo service"
	defaultICAPISTag   = "CI0001-XXXXXXXXX"
)

// storeICAP persists encapsulated bodies; replaced in tests.
var storeICAP = func(data []byte) (string, error) {
	return helpers.Store(data, filepath.Join("payloads", "icap"))
}

func icapPersona() icap.Persona {
	p := icap.Persona{Server: defaultICAPServer, Service: defaultICAPService, ISTag: defaultICAPISTag}
	if v := viper.GetString("icap.service"); v != "" {
		p.Service = v
	}
	if v := viper.GetString("icap.istag"); v != "" {
		p.ISTag = v
	}
	return p
}

type parsedICAP struct {
	Direction    string `json:"direction,omitempty"`
	Command      string `json:"command,omitempty"` // ICAP method
	Path         string `json:"path,omitempty"`    // service path of the ICAP URI
	Status       string `json:"status,omitempty"`  // ICAP status code on writes
	UserAgent    string `json:"user_agent,omitempty"`
	Encapsulated string `json:"encapsulated,omitempty"`
	Preview      string `json:"preview,omitempty"`
	HTTPRequest  string `json:"http_request,omitempty"` // encapsulated HTTP request line
	HTTPStatus   string `json:"http_status,omitempty"`  // encapsulated HTTP status line
	PayloadHash  string `json:"payload_hash,omitempty"` // SHA-256 of the stored body
	Payload      []byte `json:"payload,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
}

type icapServer struct {
	events  []parsedICAP
	conn    net.Conn
	reader  *bufio.Reader
	persona icap.Persona
	// now dates the replies; tests pin it.
	now func() time.Time
}

func newICAPServer(conn net.Conn) *icapServer {
	return &icapServer{
		events:  []parsedICAP{},
		conn:    conn,
		reader:  bufio.NewReader(conn),
		persona: icapPersona(),
		now:     time.Now,
	}
}

func (s *icapServer) read() (icap.Request, error) {
	req, raw, truncated, err := icap.ReadRequest(s.reader, icapMaxBody)
	if len(raw) == 0 {
		return req, err
	}
	s.events = append(s.events, parsedICAP{
		Direction:    "read",
		Command:      req.Method,
		Path:         req.Service,
		UserAgent:    req.Header("User-Agent"),
		Encapsulated: req.Header("Encapsulated"),
		Preview:      req.Header("Preview"),
		HTTPRequest:  req.HTTPRequestLine(),
		HTTPStatus:   req.HTTPStatusLine(),
		Payload:      raw,
		Truncated:    truncated,
	})
	return req, err
}

// readRest reads the body remainder after 100 Continue into its own frame.
func (s *icapServer) readRest(req *icap.Request) error {
	body, raw, truncated, err := icap.ReadChunked(s.reader, icapMaxBody-len(req.Body))
	req.Body = append(req.Body, body...)
	if len(raw) > 0 {
		s.events = append(s.events, parsedICAP{
			Direction: "read",
			Command:   req.Method,
			Path:      req.Service,
			Payload:   raw,
			Truncated: truncated,
		})
	}
	return err
}

func (s *icapServer) write(code int, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedICAP{
		Direction: "write",
		Status:    strconv.Itoa(code),
		Payload:   data,
	})
	return nil
}

// HandleICAP takes a net.Conn and answers ICAP/1.0 (RFC 3507) as the c-icap
// echo service: OPTIONS advertises REQMOD/RESPMOD, previews get 100 Continue,
// and adapted messages come back unmodified (204 when allowed).
func HandleICAP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleICAP(ctx, newICAPServer(conn), md, logger, h)
}

func handleICAP(ctx context.Context, server *icapServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("icap", conn, md, helpers.FirstOrEmpty[parsedICAP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "icap"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close ICAP connection", slog.String("protocol", "icap"), producer.ErrAttr(err))
		}
	}()

	// readFailed maps a read error to the end reason; malformed input gets a
	// 400 like c-icap sends and is returned to the caller.
	readFailed := func(err error) error {
		if errors.Is(err, icap.ErrMalformed) || errors.Is(err, icap.ErrLineTooLong) || errors.Is(err, icap.ErrBodyTooLarge) {
			logger.Debug("Malformed ICAP request", slog.String("protocol", "icap"), producer.ErrAttr(err))
			endReason = connection.EndReadError
			if werr := server.write(400, icap.BuildStatus(400, server.persona, server.now())); werr != nil {
				logger.Debug("Failed to write ICAP error", slog.String("protocol", "icap"), producer.ErrAttr(werr))
			}
			return err
		}
		logger.Debug("Failed to read data", slog.String("protocol", "icap"), producer.ErrAttr(err))
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		endReason = connection.EndReasonFromRead(err)
		return nil
	}

	for i := 0; i < icapMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "icap"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			return readFailed(err)
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("ICAP request received",
				slog.String("handler", "icap"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("method", req.Method),
				slog.String("service", req.Service),
			)
		}

		code := 200
		var resp []byte
		switch req.Method {
		case icap.MethodOptions:
			resp = icap.BuildOptions(server.persona, server.now())
		case icap.MethodReqmod, icap.MethodRespmod:
			if req.NeedsContinue() {
				if err := server.write(100, icap.BuildContinue()); err != nil {
					logger.Error("Failed to write ICAP response", slog.String("protocol", "icap"), producer.ErrAttr(err))
					endReason = connection.EndWriteError
					return err
				}
				if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
					logger.Debug("Failed to set connection timeout", slog.String("protocol", "icap"), producer.ErrAttr(err))
					endReason = connection.EndTimeout
					return nil
				}
				if err := server.readRest(&req); err != nil {
					return readFailed(err)
				}
			}
			if len(req.Body) > 0 {
				hash, err := storeICAP(req.Body)
				if err != nil {
					logger.Error("Failed to store ICAP body", slog.String("protocol", "icap"), producer.ErrAttr(err))
				} else {
					server.events[len(server.events)-1].PayloadHash = hash
				}
			}
			if req.Allows204() {
				code = 204
				resp = icap.BuildStatus(code, server.persona, server.now())
			} else {
				resp = icap.BuildEcho(req, server.persona, server.now())
			}
		default:
			code = 405
			resp = icap.BuildStatus(code, server.persona, server.now())
		}
		if err := server.write(code, resp); err != nil {
			logger.Error("Failed to write ICAP response", slog.String("protocol", "icap"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
		if strings.EqualFold(req.Header("Connection"), "close") {
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
