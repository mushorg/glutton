package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/citrix"
	"github.com/mushorg/glutton/protocols/tcp/ja4h"
	"github.com/mushorg/glutton/protocols/tcp/log4shell"
	"github.com/mushorg/glutton/protocols/tcp/php2shell"
	"github.com/mushorg/glutton/protocols/tcp/pve"
	"github.com/mushorg/glutton/protocols/tcp/selenium"
)

const (
	maxHTTPRequests   = 50
	maxHTTPBody       = 1 << 20 // 1 MiB
	httpSessionCookie = "session"
)

var httpSessions = newSessionTable[parsedHTTP]()

// httpNow stamps persona Date headers; tests swap it.
var httpNow = time.Now

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

func httpOKJSON(data []byte) []byte {
	return append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(data))), data...)
}

func handlePOST(req *http.Request, body []byte, logger interfaces.Logger) ([]byte, error) {
	// Ethereum RPC call
	if strings.Contains(string(body), "eth_blockNumber") {
		data, err := handleEthereumRPC(body)
		if err != nil {
			return nil, err
		}
		return httpOKJSON(data), nil
	}
	// Hadoop YARN hack
	if strings.Contains(req.RequestURI, "cluster/apps/new-application") {
		resp, err := json.Marshal(
			&struct {
				ApplicationID             string      `json:"application-id"`
				MaximumResourceCapability interface{} `json:"maximum-resource-capability"`
			}{
				ApplicationID: "application_1527144634877_20465",
				MaximumResourceCapability: struct {
					Memory int `json:"memory"`
					VCores int `json:"vCores"`
				}{
					Memory: 16384,
					VCores: 8,
				},
			},
		)
		if err != nil {
			return nil, err
		}
		logger.Info("sending hadoop yarn hack response")
		return httpOKJSON(resp), nil
	}
	return nil, nil
}

type parsedHTTP struct {
	Direction  string             `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command    string             `json:"command,omitempty"`   // HTTP method
	Path       string             `json:"path,omitempty"`
	Query      string             `json:"query,omitempty"`
	Parameters url.Values         `json:"parameters,omitempty"` // parsed query key/values
	Host       string             `json:"host,omitempty"`
	Username   string             `json:"username,omitempty"` // HTTP Basic or Proxmox VE login
	Password   string             `json:"password,omitempty"` // HTTP Basic or Proxmox VE login
	UserAgent  string             `json:"user_agent,omitempty"`
	JA4H       string             `json:"ja4h,omitempty"` // FoxIO JA4H fingerprint of the request, set on reads
	Status     string             `json:"status,omitempty"`
	SessionID  string             `json:"session_id,omitempty"`
	DestPort   uint16             `json:"dest_port,omitempty"` // set on reads; sessions can span ports
	SrcPort    string             `json:"src_port,omitempty"`  // set on reads; sessions can span connections
	Browser    string             `json:"browser,omitempty"`   // Selenium new-session browserName
	Binary     string             `json:"binary,omitempty"`    // Selenium new-session browser binary
	Args       []string           `json:"args,omitempty"`      // Selenium new-session browser args
	Truncated  bool               `json:"truncated,omitempty"` // a Selenium binary/args cap applied
	Citrix     *citrix.Request    `json:"citrix,omitempty"`    // CVE-2019-19781 stage, NSC_USER, template
	Log4Shell  *log4shell.Request `json:"log4shell,omitempty"` // CVE-2021-44228 JNDI lookups (parse-only)
	PHP2Shell  *php2shell.Request `json:"php2shell,omitempty"` // CVE-2026-109618/109619 multipart shape (parse-only)
	Payload    []byte             `json:"payload,omitempty"`   // raw HTTP request or response bytes
}

// httpParameters returns the query map, or nil when empty so omitempty drops it.
func httpParameters(q url.Values) url.Values {
	if len(q) == 0 {
		return nil
	}
	return q
}

func stampHTTP(frame *parsedHTTP, id string) {
	frame.SessionID = id
}

func httpPayload(events []parsedHTTP) []byte {
	return helpers.FirstOrEmpty(events).Payload
}

type httpServer struct {
	sessionTracker[parsedHTTP]
	conn  net.Conn
	bufin *bufio.Reader
	// tunnel marks HTTP carried inside another handler's connection (SOCKS):
	// frames stay local (no session grouping), there is no MCP handoff, and
	// tunnelReply replaces the empty 200 for requests nothing else answers.
	tunnel      bool
	tunnelReply []byte
}

func newHTTPServer(conn net.Conn) *httpServer {
	srcHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &httpServer{
		sessionTracker: sessionTracker[parsedHTTP]{
			local:   []parsedHTTP{},
			srcHost: srcHost,
			table:   httpSessions,
			spec: sessionSpec[parsedHTTP]{
				protocol:      "http",
				payload:       httpPayload,
				stamp:         stampHTTP,
				groupBySource: true,
			},
			remote: conn.RemoteAddr(),
		},
		conn:  conn,
		bufin: bufio.NewReader(conn),
	}
}

func addHeaderAfterStatus(resp []byte, name, value string) []byte {
	needle := []byte("\r\n" + strings.ToLower(name) + ":")
	if bytes.Contains(bytes.ToLower(resp), needle) {
		return resp
	}
	idx := bytes.Index(resp, []byte("\r\n"))
	if idx < 0 {
		return resp
	}
	header := []byte(fmt.Sprintf("%s: %s\r\n", name, value))
	out := make([]byte, 0, len(resp)+len(header))
	out = append(out, resp[:idx+2]...)
	out = append(out, header...)
	out = append(out, resp[idx+2:]...)
	return out
}

func httpStatusCode(resp []byte) string {
	line, _, _ := bytes.Cut(resp, []byte("\r\n"))
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) >= 2 && bytes.HasPrefix(parts[0], []byte("HTTP/")) {
		return string(parts[1])
	}
	return ""
}

func (s *httpServer) write(data []byte) error {
	if s.sessionID != "" {
		data = addHeaderAfterStatus(data, "Set-Cookie", httpSessionCookie+"="+s.sessionID)
	}
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.record(parsedHTTP{
		Direction: "write",
		Status:    httpStatusCode(data),
		Payload:   data,
	})
	return nil
}

func (s *httpServer) handleRequest(ctx context.Context, req *http.Request, raw []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer req.Body.Close()
	path := req.URL.EscapedPath()
	params := req.URL.Query()
	query := params.Encode()
	body, _ := io.ReadAll(req.Body)

	if s.tunnel {
		// frames stay in s.local for the parent handler to embed
	} else if c, err := req.Cookie(httpSessionCookie); err == nil && strings.TrimSpace(c.Value) != "" {
		s.bind(strings.TrimSpace(c.Value))
	} else {
		s.ensure()
	}

	_, srcPort, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	frame := parsedHTTP{
		Direction:  "read",
		DestPort:   md.TargetPort,
		SrcPort:    srcPort,
		Command:    req.Method,
		Path:       path,
		Query:      query,
		Parameters: httpParameters(params),
		Host:       req.Host,
		UserAgent:  req.UserAgent(),
		JA4H:       ja4h.Fingerprint(raw),
		Payload:    raw,
	}
	if user, pass, ok := req.BasicAuth(); ok {
		frame.Username, frame.Password = user, pass
	}
	grid := selenium.IsGridRequest(md.TargetPort, path)
	if grid {
		if sess, ok := selenium.NewSessionRequest(req.Method, path, body); ok {
			frame.Browser, frame.Binary, frame.Args, frame.Truncated = sess.Browser, sess.Binary, sess.Args, sess.Truncated
		}
	}
	proxmox := md.TargetPort == pve.Port
	if proxmox {
		if user, pass, ok := pve.LoginCredentials(req.Method, path, body); ok {
			frame.Username, frame.Password = user, pass
		}
	}
	frame.Citrix = citrix.Inspect(req.Method, path, req.Header, body)
	frame.Log4Shell = log4shell.Inspect(path, req.URL.RawQuery, req.Header, body)
	frame.PHP2Shell = php2shell.Inspect(req.Header, body)
	if frame.PHP2Shell != nil {
		logger.Info(
			"HTTP PHP2Shell multipart request",
			slog.String("handler", "http"),
			slog.Any("indicators", frame.PHP2Shell.Indicators),
		)
	}
	if frame.Log4Shell != nil {
		logger.Info(
			"HTTP Log4Shell JNDI lookup",
			slog.String("handler", "http"),
			slog.Int("lookups", len(frame.Log4Shell.Lookups)),
		)
	}
	s.record(frame)

	if grid {
		return s.write(selenium.Respond(req.Method, path, body))
	}
	if proxmox {
		return s.write(pve.Respond(req.Method, path, httpNow()))
	}
	if frame.Citrix != nil {
		logger.Info(
			"HTTP Citrix CVE-2019-19781 request",
			slog.String("handler", "http"),
			slog.String("stage", string(frame.Citrix.Stage)),
		)
		return s.write(citrix.Respond(frame.Citrix.Stage))
	}

	switch req.Method {
	case http.MethodPost:
		resp, err := handlePOST(req, body, logger)
		if err != nil {
			return err
		}
		if resp != nil {
			return s.write(resp)
		}
		return nil
	}

	if strings.Contains(req.RequestURI, "wallet") {
		logger.Info(
			"HTTP wallet request",
			slog.String("handler", "http"),
		)
		return s.write([]byte("HTTP/1.1 200 OK\r\nContent-Length:6\r\n\r\n[[\"\"]]"))
	}

	if strings.Contains(req.RequestURI, "/v1.16/version") {
		data, err := Res.ReadFile("resources/docker_api.json")
		if err != nil {
			return fmt.Errorf("failed to read embedded file: %w", err)
		}
		return s.write(httpOKJSON(data))
	}

	pathForLFI := req.URL.EscapedPath()
	if pathForLFI == "" {
		pathForLFI = req.URL.Path
	}
	if resp := LFIResponse(pathForLFI, req.URL.RawQuery); resp != nil {
		return s.write(resp)
	}

	reply := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if s.tunnelReply != nil {
		reply = s.tunnelReply
	}
	if err := s.write(reply); err != nil {
		return fmt.Errorf("failed to send HTTP response: %w", err)
	}
	return nil
}

// HandleHTTP takes a net.Conn and does basic HTTP communication
func HandleHTTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleHTTP(ctx, newHTTPServer(conn), md, logger, h)
}

func handleHTTP(ctx context.Context, server *httpServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn

	handoff := false
	endReason := connection.EndHandlerClose
	defer func() {
		if handoff {
			return
		}
		server.md.EndReason = endReason
		server.closeAndProduce(conn)
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close the HTTP connection", slog.String("protocol", "http"), producer.ErrAttr(err))
		}
	}()

	reason, mcpRaw := server.serve(ctx, md, logger, h)
	endReason = reason
	if mcpRaw != nil {
		handoff = true
		return HandleMCP(ctx, PrependConn(conn, mcpRaw), md.WithOuter("http"), logger, h)
	}
	return nil
}

// serve runs the HTTP request loop on s.conn and records frames on s. It does
// not produce an event or close the connection. When the first request targets
// an MCP endpoint (and s is not a tunnel) it stops and returns that request's
// raw bytes so the caller can hand the connection to MCP.
func (s *httpServer) serve(ctx context.Context, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (endReason string, mcpRaw []byte) {
	s.md = md
	s.logger = logger
	s.h = h
	conn := s.conn
	endReason = connection.EndHandlerClose

	srcHost, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxHTTPRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "http"), producer.ErrAttr(err))
			return connection.EndTimeout, nil
		}

		raw, err := readHTTPMessage(s.bufin, maxHTTPBody)
		if len(raw) > 0 {
			req, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
			if parseErr != nil {
				logger.Debug("Failed to read the HTTP request", slog.String("protocol", "http"), producer.ErrAttr(parseErr))
				s.record(parsedHTTP{Direction: "read", Payload: append([]byte(nil), raw...)})
				return connection.EndReadError, nil
			}

			if i == 0 && !s.tunnel && IsMCPPath(req.URL.EscapedPath()) {
				return endReason, raw
			}

			logger.Info(
				fmt.Sprintf("HTTP %s request handled: %s", req.Method, req.URL.EscapedPath()),
				slog.String("handler", "http"),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("src_ip", srcHost),
				slog.String("src_port", srcPort),
				slog.String("path", req.URL.EscapedPath()),
				slog.String("method", req.Method),
				slog.String("query", req.URL.Query().Encode()),
			)

			if handleErr := s.handleRequest(ctx, req, raw, md, logger, h); handleErr != nil {
				logger.Debug("Failed to handle HTTP request", slog.String("protocol", "http"), producer.ErrAttr(handleErr))
				return connection.EndWriteError, nil
			}
		}
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "http"), producer.ErrAttr(err))
			return connection.EndReasonFromRead(err), nil
		}
	}
	return endReason, nil
}
