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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

const (
	maxMCPRequests = 50
	maxMCPBody     = 1 << 20 // 1 MiB
	mcpServerName  = "mcp"
	mcpServerVer   = "1.0.0"
	mcpProtoVer    = "2025-06-18"
)

// mcpSessionIdle overrides the session flush delay in tests. When zero,
// production uses conn_timeout (default 45s) so follow-up requests on new
// connections can still append to the same produced event.
var mcpSessionIdle time.Duration

func mcpSessionIdleDuration() time.Duration {
	if mcpSessionIdle > 0 {
		return mcpSessionIdle
	}
	if secs := viper.GetInt("conn_timeout"); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 45 * time.Second
}

var mcpContentLenRE = regexp.MustCompile(`(?i)Content-Length:\s*(\d+)`)

// parsedMCP is one frame of an MCP-over-HTTP session.
type parsedMCP struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // JSON-RPC method, or HTTP verb when no JSON body
	Path      string `json:"path,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Payload   []byte `json:"payload,omitempty"` // raw HTTP request or response bytes
}

// mcpSession aggregates frames across TCP connections that share an MCP session id.
type mcpSession struct {
	mu        sync.Mutex
	id        string
	key       string
	events    []parsedMCP
	md        connection.Metadata
	remote    net.Addr
	h         interfaces.Honeypot
	logger    interfaces.Logger
	refs      int
	idleTimer *time.Timer
	produced  bool
}

type mcpSessionTable struct {
	mu       sync.Mutex
	sessions map[string]*mcpSession
}

var mcpSessions = &mcpSessionTable{sessions: map[string]*mcpSession{}}

func mcpSessionKey(srcHost, sessionID string) string {
	return srcHost + "|" + sessionID
}

func (t *mcpSessionTable) get(key string) *mcpSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[key]
}

func (t *mcpSessionTable) put(s *mcpSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[s.key] = s
}

func (t *mcpSessionTable) remove(key string, expected *mcpSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.sessions[key]; ok && current == expected {
		delete(t.sessions, key)
	}
}

// remoteAddrConn exposes a stored remote address for ProduceTCP after the real conn closed.
type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func (s *mcpSession) append(frames ...parsedMCP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced {
		return
	}
	for i := range frames {
		frames[i].SessionID = s.id
	}
	s.events = append(s.events, frames...)
	s.stopIdleLocked()
}

func (s *mcpSession) acquire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs++
	s.stopIdleLocked()
}

func (s *mcpSession) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs > 0 {
		s.refs--
	}
	if s.refs == 0 && !s.produced {
		s.armIdleLocked()
	}
}

func (s *mcpSession) stopIdleLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

func (s *mcpSession) armIdleLocked() {
	s.stopIdleLocked()
	s.idleTimer = time.AfterFunc(mcpSessionIdleDuration(), s.produce)
}

func (s *mcpSession) produce() {
	s.mu.Lock()
	if s.produced {
		s.mu.Unlock()
		return
	}
	s.produced = true
	s.stopIdleLocked()
	events := append([]parsedMCP(nil), s.events...)
	md := s.md
	remote := s.remote
	h := s.h
	logger := s.logger
	key := s.key
	s.mu.Unlock()

	mcpSessions.remove(key, s)

	if len(events) == 0 || h == nil {
		return
	}
	conn := &remoteAddrConn{remote: remote}
	if err := h.ProduceTCP("mcp", conn, md, helpers.FirstOrEmpty[parsedMCP](events).Payload, events); err != nil {
		logger.Error("Failed to produce message", slog.String("protocol", "mcp"), producer.ErrAttr(err))
	}
}

func (s *mcpSession) endNow() {
	s.mu.Lock()
	s.refs = 0
	s.mu.Unlock()
	s.produce()
}

type mcpServer struct {
	local     []parsedMCP
	session   *mcpSession
	conn      net.Conn
	bufin     *bufio.Reader
	sessionID string
	srcHost   string
	md        connection.Metadata
	logger    interfaces.Logger
	h         interfaces.Honeypot
}

func newMCPServer(conn net.Conn) *mcpServer {
	srcHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &mcpServer{
		local:   []parsedMCP{},
		conn:    conn,
		bufin:   bufio.NewReader(conn),
		srcHost: srcHost,
	}
}

// PrependConn returns a conn whose Read first drains prefix, then the underlying conn.
func PrependConn(conn net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &readerConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// IsMCPPath reports whether an HTTP path is an MCP (or legacy SSE) endpoint.
func IsMCPPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path == "/mcp" || strings.HasPrefix(path, "/mcp/") || path == "/sse"
}

// LooksLikeMCP reports whether the start of an HTTP request targets an MCP endpoint.
func LooksLikeMCP(snip []byte) bool {
	// Request-line forms: "POST /mcp HTTP/1.1", "GET /mcp?...", "POST /sse HTTP/1.1"
	lower := bytes.ToLower(snip)
	return bytes.Contains(lower, []byte(" /mcp ")) ||
		bytes.Contains(lower, []byte(" /mcp?")) ||
		bytes.Contains(lower, []byte(" /mcp/")) ||
		bytes.Contains(lower, []byte(" /sse ")) ||
		bytes.Contains(lower, []byte(" /sse?"))
}

func (s *mcpServer) bindSession(id string) {
	if id == "" {
		return
	}
	if s.session != nil && s.session.id == id {
		s.sessionID = id
		return
	}
	if s.session != nil {
		s.session.release()
		s.session = nil
	}

	key := mcpSessionKey(s.srcHost, id)
	sess := mcpSessions.get(key)
	if sess == nil {
		sess = &mcpSession{
			id:     id,
			key:    key,
			events: []parsedMCP{},
			md:     s.md,
			remote: s.conn.RemoteAddr(),
			h:      s.h,
			logger: s.logger,
		}
		mcpSessions.put(sess)
	}
	sess.acquire()
	if len(s.local) > 0 {
		sess.append(s.local...)
		s.local = nil
	}
	s.session = sess
	s.sessionID = id
}

func (s *mcpServer) ensureSession() {
	if s.session != nil {
		return
	}
	s.bindSession(uuid.NewString())
}

func (s *mcpServer) record(frame parsedMCP) {
	frame.SessionID = s.sessionID
	if s.session != nil {
		s.session.append(frame)
		return
	}
	s.local = append(s.local, frame)
}

func (s *mcpServer) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.record(parsedMCP{
		Direction: "write",
		Payload:   data,
	})
	return nil
}

func (s *mcpServer) recordRead(command, path string, payload []byte) {
	s.record(parsedMCP{
		Direction: "read",
		Command:   command,
		Path:      path,
		Payload:   payload,
	})
}

func (s *mcpServer) readHTTPMessage() ([]byte, error) {
	raw := make([]byte, 0, 4096)
	for {
		line, err := s.bufin.ReadBytes('\n')
		if len(line) > 0 {
			raw = append(raw, line...)
		}
		if err != nil {
			if len(raw) > 0 {
				return raw, err
			}
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}

	clen := 0
	if m := mcpContentLenRE.FindSubmatch(raw); m != nil {
		clen, _ = strconv.Atoi(string(m[1]))
	}
	if clen < 0 || clen > maxMCPBody {
		return raw, fmt.Errorf("content-length %d out of range", clen)
	}
	if clen > 0 {
		body := make([]byte, clen)
		if _, err := io.ReadFull(s.bufin, body); err != nil {
			return raw, err
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

type mcpJSONRPC struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mcpHTTPResponse(status int, extraHeaders map[string]string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	b.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	for k, v := range extraHeaders {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

func mcpResult(id json.RawMessage, result interface{}) ([]byte, error) {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  interface{}     `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	return json.Marshal(resp)
}

func mcpErr(id json.RawMessage, code int, message string) ([]byte, error) {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Error   mcpError        `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error:   mcpError{Code: code, Message: message},
	}
	return json.Marshal(resp)
}

func mcpInitializeResult(clientProto string) map[string]interface{} {
	proto := mcpProtoVer
	if clientProto != "" {
		proto = clientProto
	}
	return map[string]interface{}{
		"protocolVersion": proto,
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{"listChanged": false},
			"resources": map[string]interface{}{"subscribe": false, "listChanged": false},
			"prompts":   map[string]interface{}{"listChanged": false},
		},
		"serverInfo": map[string]interface{}{
			"name":    mcpServerName,
			"version": mcpServerVer,
		},
	}
}

func mcpToolsListResult() map[string]interface{} {
	return map[string]interface{}{
		"tools": []map[string]interface{}{
			{
				"name":        "echo",
				"description": "Echo a message back to the caller",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"message": map[string]interface{}{"type": "string"},
					},
				},
			},
		},
	}
}

func mcpResourcesListResult() map[string]interface{} {
	return map[string]interface{}{
		"resources": []interface{}{},
	}
}

func mcpPromptsListResult() map[string]interface{} {
	return map[string]interface{}{
		"prompts": []interface{}{},
	}
}

func mcpToolsCallResult(params json.RawMessage) map[string]interface{} {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Message string `json:"message"`
		} `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	msg := p.Arguments.Message
	if msg == "" {
		msg = p.Name
	}
	if msg == "" {
		msg = "ok"
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": msg},
		},
		"isError": false,
	}
}

func clientProtocolVersion(params json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	return p.ProtocolVersion
}

func (s *mcpServer) handleJSONRPC(rawReq mcpJSONRPC) ([]byte, error) {
	// Notifications have no id and must not receive a response.
	isNotification := len(rawReq.ID) == 0 || string(rawReq.ID) == "null"

	switch rawReq.Method {
	case "initialize":
		s.ensureSession()
		body, err := mcpResult(rawReq.ID, mcpInitializeResult(clientProtocolVersion(rawReq.Params)))
		if err != nil {
			return nil, err
		}
		headers := map[string]string{"Mcp-Session-Id": s.sessionID}
		return mcpHTTPResponse(http.StatusOK, headers, body), nil

	case "notifications/initialized":
		return nil, nil

	case "ping":
		if isNotification {
			return nil, nil
		}
		body, err := mcpResult(rawReq.ID, map[string]interface{}{})
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil

	case "tools/list":
		body, err := mcpResult(rawReq.ID, mcpToolsListResult())
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil

	case "resources/list":
		body, err := mcpResult(rawReq.ID, mcpResourcesListResult())
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil

	case "prompts/list":
		body, err := mcpResult(rawReq.ID, mcpPromptsListResult())
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil

	case "tools/call":
		body, err := mcpResult(rawReq.ID, mcpToolsCallResult(rawReq.Params))
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil

	default:
		if isNotification {
			return nil, nil
		}
		body, err := mcpErr(rawReq.ID, -32601, "Method not found")
		if err != nil {
			return nil, err
		}
		return mcpHTTPResponse(http.StatusOK, nil, body), nil
	}
}

func (s *mcpServer) handleRequest(raw []byte) error {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		s.recordRead("", "", raw)
		return s.write(mcpHTTPResponse(http.StatusBadRequest, nil, []byte(`{"error":"bad request"}`)))
	}
	defer req.Body.Close()

	path := req.URL.EscapedPath()
	body, _ := io.ReadAll(req.Body)

	if sid := strings.TrimSpace(req.Header.Get("Mcp-Session-Id")); sid != "" {
		s.bindSession(sid)
	}

	command := strings.ToUpper(req.Method)
	var rpc mcpJSONRPC
	if len(body) > 0 && json.Unmarshal(body, &rpc) == nil && rpc.Method != "" {
		command = rpc.Method
	}
	s.recordRead(command, path, raw)

	switch req.Method {
	case http.MethodPost:
		if len(body) == 0 {
			return s.write(mcpHTTPResponse(http.StatusBadRequest, nil, []byte(`{"error":"empty body"}`)))
		}
		if err := json.Unmarshal(body, &rpc); err != nil {
			bodyErr, _ := mcpErr(nil, -32700, "Parse error")
			return s.write(mcpHTTPResponse(http.StatusOK, nil, bodyErr))
		}
		resp, err := s.handleJSONRPC(rpc)
		if err != nil {
			return err
		}
		if resp == nil {
			// Notification: Streamable HTTP accepts with 202 and empty body.
			return s.write([]byte("HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"))
		}
		return s.write(resp)

	case http.MethodGet:
		// Minimal SSE open for clients that negotiate event-stream first.
		sse := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n: connected\n\n"
		return s.write([]byte(sse))

	case http.MethodDelete:
		err := s.write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		if s.session != nil {
			s.session.endNow()
			s.session = nil
		}
		return err

	default:
		return s.write(mcpHTTPResponse(http.StatusMethodNotAllowed, nil, []byte(`{"error":"method not allowed"}`)))
	}
}

func (s *mcpServer) closeAndProduce() {
	if s.session != nil {
		s.session.release()
		s.session = nil
		return
	}
	if len(s.local) == 0 || s.h == nil {
		return
	}
	if err := s.h.ProduceTCP("mcp", s.conn, s.md, helpers.FirstOrEmpty[parsedMCP](s.local).Payload, s.local); err != nil {
		s.logger.Error("Failed to produce message", slog.String("protocol", "mcp"), producer.ErrAttr(err))
	}
}

// HandleMCP speaks MCP over Streamable HTTP (JSON-RPC), keeping the connection
// alive past initialize so scanners can continue with tools/list and related calls.
// Frames from connections that share an Mcp-Session-Id (per source host) are
// grouped into one produced event when the session idles out or is deleted.
func HandleMCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleMCP(ctx, newMCPServer(conn), md, logger, h)
}

func handleMCP(ctx context.Context, server *mcpServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	server.md = md
	server.logger = logger
	server.h = h

	defer func() {
		server.closeAndProduce()
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MCP connection", slog.String("protocol", "mcp"), producer.ErrAttr(err))
		}
	}()

	srcHost, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	logger.Info("MCP connection handled",
		slog.String("handler", "mcp"),
		slog.String("src_ip", srcHost),
		slog.String("src_port", srcPort),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
	)

	for i := 0; i < maxMCPRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "mcp"), producer.ErrAttr(err))
			return nil
		}

		raw, err := server.readHTTPMessage()
		if len(raw) > 0 {
			if handleErr := server.handleRequest(raw); handleErr != nil {
				logger.Debug("Failed to handle MCP request", slog.String("protocol", "mcp"), producer.ErrAttr(handleErr))
				return nil
			}
		}
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "mcp"), producer.ErrAttr(err))
			break
		}
	}
	return nil
}
