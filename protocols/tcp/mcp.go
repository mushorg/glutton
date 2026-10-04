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

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxMCPRequests = 50
	maxMCPBody     = 1 << 20 // 1 MiB
	mcpServerName  = "mcp"
	mcpServerVer   = "1.0.0"
	mcpProtoVer    = "2025-06-18"
)

var mcpContentLenRE = regexp.MustCompile(`(?i)Content-Length:\s*(\d+)`)

var mcpSessions = newSessionTable[parsedMCP]()

// parsedMCP is one frame of an MCP-over-HTTP session.
type parsedMCP struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // JSON-RPC method, or HTTP verb when no JSON body
	Path      string `json:"path,omitempty"`
	Status    string `json:"status,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Payload   []byte `json:"payload,omitempty"` // raw HTTP request or response bytes
}

func stampMCP(frame *parsedMCP, id string) {
	frame.SessionID = id
}

func mcpPayload(events []parsedMCP) []byte {
	return helpers.FirstOrEmpty(events).Payload
}

type mcpServer struct {
	sessionTracker[parsedMCP]
	conn  net.Conn
	bufin *bufio.Reader
}

func newMCPServer(conn net.Conn) *mcpServer {
	srcHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &mcpServer{
		sessionTracker: sessionTracker[parsedMCP]{
			local:   []parsedMCP{},
			srcHost: srcHost,
			table:   mcpSessions,
			spec: sessionSpec[parsedMCP]{
				protocol: "mcp",
				payload:  mcpPayload,
				stamp:    stampMCP,
			},
			remote: conn.RemoteAddr(),
		},
		conn:  conn,
		bufin: bufio.NewReader(conn),
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

func (s *mcpServer) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.record(parsedMCP{
		Direction: "write",
		Status:    httpStatusCode(data),
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

func readHTTPMessage(bufin *bufio.Reader, maxBody int) ([]byte, error) {
	raw := make([]byte, 0, 4096)
	for {
		line, err := bufin.ReadBytes('\n')
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
	if clen < 0 || clen > maxBody {
		return raw, fmt.Errorf("content-length %d out of range", clen)
	}
	if clen > 0 {
		body := make([]byte, clen)
		if _, err := io.ReadFull(bufin, body); err != nil {
			return raw, err
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

func (s *mcpServer) readHTTPMessage() ([]byte, error) {
	return readHTTPMessage(s.bufin, maxMCPBody)
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
		s.ensure()
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
		s.bind(sid)
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
	s.sessionTracker.closeAndProduce(s.conn)
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

	endReason := connection.EndHandlerClose
	defer func() {
		server.md.EndReason = endReason
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

	i := 0
	for ; i < maxMCPRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "mcp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		raw, err := server.readHTTPMessage()
		if len(raw) > 0 {
			if handleErr := server.handleRequest(raw); handleErr != nil {
				logger.Debug("Failed to handle MCP request", slog.String("protocol", "mcp"), producer.ErrAttr(handleErr))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "mcp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
	}
	if i >= maxMCPRequests {
		endReason = connection.EndMaxFrames
	}
	return nil
}
