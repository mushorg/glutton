package banners

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Shodan probes ports with a JSON-RPC 2.0 "initialize" request in base-protocol
// framing: a "Content-Length: N\r\n\r\n" header block followed by N bytes of
// JSON (Shodan, tcp/2087: `{"params": {}, "jsonrpc": "2.0", "id": 1,
// "method": "initialize"}`). That framing is the LSP base protocol, which MCP
// servers bridged from stdio to a socket also speak. A server answers each
// request in the same framing and sends nothing back for notifications. The
// persona is the same generic MCP server the HTTP /mcp handler (mcp.go)
// presents; the banners package cannot import it, so the values are repeated.

const (
	jsonrpcServerName  = "mcp"
	jsonrpcServerVer   = "1.0.0"
	jsonrpcProtoVer    = "2025-06-18"
	jsonrpcMaxMessages = 8
)

// jsonrpcRequest is one framed JSON-RPC message from the client.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonrpcInitializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    map[string]any    `json:"capabilities"`
	ServerInfo      jsonrpcServerInfo `json:"serverInfo"`
}

// splitJSONRPCFrame cuts one "Content-Length" framed message off the front of
// data. Header names are case-insensitive; other headers (Content-Type) are
// allowed. It fails unless the whole body is present.
func splitJSONRPCFrame(data []byte) (body, rest []byte, ok bool) {
	header, after, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		return nil, nil, false
	}
	length := -1
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			return nil, nil, false
		}
		if bytes.EqualFold(bytes.TrimSpace(name), []byte("Content-Length")) {
			n, err := strconv.Atoi(string(bytes.TrimSpace(value)))
			if err != nil || n <= 0 {
				return nil, nil, false
			}
			length = n
		}
	}
	if length < 0 || len(after) < length {
		return nil, nil, false
	}
	return after[:length], after[length:], true
}

// isJSONRPCNotification reports whether the message has no id, so it must
// not be answered.
func isJSONRPCNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == "null"
}

// jsonrpcResult builds the reply to one request.
func jsonrpcResult(req jsonrpcRequest) jsonrpcResponse {
	resp := jsonrpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		proto := jsonrpcProtoVer
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(req.Params, &p) == nil && p.ProtocolVersion != "" {
			proto = p.ProtocolVersion
		}
		resp.Result = jsonrpcInitializeResult{
			ProtocolVersion: proto,
			Capabilities: map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"subscribe": false, "listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			ServerInfo: jsonrpcServerInfo{Name: jsonrpcServerName, Version: jsonrpcServerVer},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": []map[string]any{{
			"name":        "echo",
			"description": "Echo a message back to the caller",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"message": map[string]any{"type": "string"}},
			},
		}}}
	case "resources/list":
		resp.Result = map[string]any{"resources": []any{}}
	case "prompts/list":
		resp.Result = map[string]any{"prompts": []any{}}
	default:
		resp.Error = &jsonrpcError{Code: -32601, Message: "Method not found"}
	}
	return resp
}

// jsonrpcReply answers Content-Length framed JSON-RPC 2.0 messages. Every
// complete message in data must be valid JSON-RPC 2.0 with a method; requests
// get a framed reply each, and a read holding only notifications gets none.
func jsonrpcReply(data []byte) (Response, bool) {
	if len(data) == 0 {
		return Response{}, false
	}
	var out []byte
	rest := data
	for n := 0; len(rest) > 0; n++ {
		if n == jsonrpcMaxMessages {
			return Response{}, false
		}
		var body []byte
		var ok bool
		if body, rest, ok = splitJSONRPCFrame(rest); !ok {
			return Response{}, false
		}
		var req jsonrpcRequest
		if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			return Response{}, false
		}
		if isJSONRPCNotification(req.ID) {
			continue
		}
		msg, err := json.Marshal(jsonrpcResult(req))
		if err != nil {
			return Response{}, false
		}
		out = append(out, "Content-Length: "+strconv.Itoa(len(msg))+"\r\n\r\n"...)
		out = append(out, msg...)
	}
	if out == nil {
		return Response{Name: "jsonrpc", NoReply: true}, true
	}
	return Response{Name: "jsonrpc", Data: out}, true
}
