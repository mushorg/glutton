package handlers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/protocols/tcp"
	"github.com/mushorg/glutton/protocols/tcp/selenium"
)

const maxHTTPRequests = 50

// parsedHTTP is one frame of the Spicy HTTP session. Host and other request
// headers are omitted from the decoded shape so the sensor address is not
// published; Payload keeps the raw wire bytes for replay.
type parsedHTTP struct {
	Direction  string     `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command    string     `json:"command,omitempty"`   // HTTP method
	Path       string     `json:"path,omitempty"`
	Query      string     `json:"query,omitempty"`
	Parameters url.Values `json:"parameters,omitempty"` // parsed query key/values
	Status     string     `json:"status,omitempty"`
	Browser    string     `json:"browser,omitempty"`   // Selenium new-session browserName
	Binary     string     `json:"binary,omitempty"`    // Selenium new-session browser binary
	Args       []string   `json:"args,omitempty"`      // Selenium new-session browser args
	Truncated  bool       `json:"truncated,omitempty"` // a Selenium binary/args cap applied
	Payload    []byte     `json:"payload,omitempty"`   // raw HTTP request or response bytes
}

// httpParameters parses a raw query string into url.Values, or nil when empty.
func httpParameters(rawQuery string) url.Values {
	if rawQuery == "" {
		return nil
	}
	v, err := url.ParseQuery(rawQuery)
	if err != nil || len(v) == 0 {
		return nil
	}
	return v
}

// requestPathAndQuery returns path and query without scheme or host, so
// absolute-form targets like http://<sensor-ip>/foo do not leak the sensor IP.
func requestPathAndQuery(uriRaw, path, query string) (string, string) {
	if u, err := url.ParseRequestURI(uriRaw); err == nil && u.Host != "" {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, u.RawQuery
	}
	if path == "" {
		path = uriRaw
	}
	return path, query
}

func httpOKJSON(data []byte) []byte {
	return append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(data))), data...)
}

func httpPlainOK() []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
}

func httpStatusCode(resp []byte) string {
	line, _, _ := bytes.Cut(resp, []byte("\r\n"))
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) >= 2 && bytes.HasPrefix(parts[0], []byte("HTTP/")) {
		return string(parts[1])
	}
	return ""
}

func ethereumRPCResponse(body []byte) []byte {
	if !bytes.Contains(body, []byte("eth_blockNumber")) {
		return nil
	}
	resp := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  string `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      0,
		Result:  "0x2ecd9e",
	}
	b, _ := json.Marshal(resp)
	return httpOKJSON(b)
}

func yarnNewApplicationResponse(method, uri string) []byte {
	if method != "POST" || !strings.Contains(uri, "cluster/apps/new-application") {
		return nil
	}
	resp, _ := json.Marshal(&struct {
		ApplicationID             string      `json:"application-id"`
		MaximumResourceCapability interface{} `json:"maximum-resource-capability"`
	}{
		ApplicationID: "application_1527144634877_20465",
		MaximumResourceCapability: struct {
			Memory int `json:"memory"`
			VCores int `json:"vCores"`
		}{Memory: 16384, VCores: 8},
	})
	return httpOKJSON(resp)
}

func walletResponse(uri string) []byte {
	if !strings.Contains(uri, "wallet") {
		return nil
	}
	body := []byte(`[[""]]`)
	return append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(body))), body...)
}

func dockerAPIVersionResponse(path string, log interfaces.Logger) []byte {
	if !strings.HasPrefix(path, "/v1.16/version") {
		return nil
	}
	data, err := tcp.Res.ReadFile("resources/docker_api.json")
	if err != nil {
		log.Error("failed to read docker_api.json", producer.ErrAttr(err))
		return nil
	}
	return httpOKJSON(data)
}

func citrixSMBResponse(path string) []byte {
	if !strings.HasPrefix(path, "/vpn/") {
		return nil
	}
	headers := `Server: Apache
X-Frame-Options: SAMEORIGIN
Last-Modified: Thu, 28 Nov 2019 20:19:22 GMT
ETag: "53-5986dd42b0680"
Accept-Ranges: bytes
Content-Length: 93
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: text/plain; charset=UTF-8`
	smbCfg := "\r\n\r\n[global]\r\n\tencrypt passwords = yes\r\n\tname resolve order = lmhosts wins host bcast\r\n"
	return []byte("HTTP/1.1 200 OK\r\n" + headers + smbCfg)
}

func handleVMwareSend(ctx context.Context, body []byte, uri string, md connection.Metadata, log interfaces.Logger, hp interfaces.Honeypot) bool {
	if !strings.Contains(uri, "hyper/send") || len(body) == 0 {
		return false
	}
	parts := strings.Split(string(body), " ")
	if len(parts) < 11 {
		return false
	}
	c, err := net.Dial("tcp", parts[9]+":"+parts[10])
	if err != nil {
		log.Error("vmware-send dial failed", producer.ErrAttr(err))
		return true
	}
	c = hp.GuardConn(c)
	go func() {
		if err := tcp.HandleTCP(ctx, c, md, log, hp); err != nil {
			log.Error("vmware-send TCP relay error", producer.ErrAttr(err))
		}
	}()
	return true
}

func bodyFromParsed(parsed *spicy.ParsedData) []byte {
	v, ok := parsed.Fields["body.content"]
	if !ok {
		return nil
	}
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}
	return nil
}

type httpServer struct {
	events []parsedHTTP
	conn   net.Conn
	bufin  *bufio.Reader
}

func newHTTPServer(conn net.Conn) *httpServer {
	return &httpServer{
		events: []parsedHTTP{},
		conn:   conn,
		bufin:  bufio.NewReader(conn),
	}
}

func (s *httpServer) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedHTTP{
		Direction: "write",
		Status:    httpStatusCode(data),
		Payload:   data,
	})
	return nil
}

func (s *httpServer) buildResponse(ctx context.Context, method, uriRaw, path string, body []byte, md connection.Metadata, log interfaces.Logger, hp interfaces.Honeypot) []byte {
	if selenium.IsGridRequest(md.TargetPort, path) {
		return selenium.Respond(method, path, body)
	}
	switch method {
	case "POST":
		if resp := ethereumRPCResponse(body); resp != nil {
			return resp
		}
		if resp := yarnNewApplicationResponse(method, uriRaw); resp != nil {
			return resp
		}
	}
	if resp := walletResponse(uriRaw); resp != nil {
		return resp
	}
	if resp := dockerAPIVersionResponse(path, log); resp != nil {
		return resp
	}
	if resp := citrixSMBResponse(path); resp != nil {
		return resp
	}
	if handleVMwareSend(ctx, body, uriRaw, md, log, hp) {
		return nil
	}
	if resp := tcp.LFIResponse(queryFromURI(uriRaw)); resp != nil {
		return resp
	}
	return httpPlainOK()
}

// queryFromURI returns the raw query string from a request-target or absolute URI.
func queryFromURI(uriRaw string) string {
	if i := strings.IndexByte(uriRaw, '?'); i >= 0 {
		q := uriRaw[i+1:]
		if j := strings.IndexAny(q, " \r\n"); j >= 0 {
			q = q[:j]
		}
		return q
	}
	if u, err := url.ParseRequestURI(uriRaw); err == nil {
		return u.RawQuery
	}
	return ""
}

// HandleHTTP takes a net.Conn and does HTTP communication using Spicy parsing.
func HandleHTTP(ctx context.Context, conn net.Conn, md connection.Metadata, log interfaces.Logger, hp interfaces.Honeypot) error {
	server := newHTTPServer(conn)
	handoff := false
	endReason := connection.EndHandlerClose
	defer func() {
		if handoff {
			return
		}
		md.EndReason = endReason
		if len(server.events) > 0 {
			if err := hp.ProduceTCP("http", conn, md, helpers.FirstOrEmpty(server.events).Payload, server.events); err != nil {
				log.Error("Failed to produce message", slog.String("protocol", "http"), producer.ErrAttr(err))
			}
		}
		if err := conn.Close(); err != nil {
			log.Debug("Failed to close HTTP connection", slog.String("protocol", "http"), producer.ErrAttr(err))
		}
	}()

	srcHost, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxHTTPRequests; i++ {
		if err := hp.UpdateConnectionTimeout(ctx, conn); err != nil {
			log.Debug("Failed to set connection timeout", slog.String("protocol", "http"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		raw, err := spicy.ReadHTTPMessage(server.bufin, spicy.MaxHTTPBody)
		if len(raw) == 0 {
			if err != nil {
				log.Debug("Failed to read data", slog.String("protocol", "http"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
			}
			break
		}

		parsed, parseErr := spicy.Parse("http", raw)
		if parseErr != nil {
			if i == 0 && len(server.events) == 0 {
				log.Debug("spicy HTTP parse failed, falling back to tcp",
					slog.String("handler", "spicy-http"), producer.ErrAttr(parseErr))
				handoff = true
				return tcp.HandleTCP(ctx, tcp.PrependConn(conn, raw), md, log, hp)
			}
			log.Debug("Failed to parse HTTP request", slog.String("protocol", "http"), producer.ErrAttr(parseErr))
			server.events = append(server.events, parsedHTTP{Direction: "read", Payload: append([]byte(nil), raw...)})
			endReason = connection.EndReadError
			break
		}

		method, _ := parsed.Fields["method"].(string)
		method = strings.ToUpper(method)
		uriRaw, _ := parsed.Fields["uri.raw"].(string)
		path, _ := parsed.Fields["uri.path"].(string)
		query, _ := parsed.Fields["uri.query"].(string)
		path, query = requestPathAndQuery(uriRaw, path, query)
		version, _ := parsed.Fields["version.number"].(string)
		body := bodyFromParsed(parsed)

		if i == 0 && tcp.IsMCPPath(path) {
			handoff = true
			return tcp.HandleMCP(ctx, tcp.PrependConn(conn, raw), md, log, hp)
		}

		log.Info(fmt.Sprintf("HTTP %s %s request handled: %s", version, method, path),
			slog.String("handler", "spicy-http"),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", srcHost),
			slog.String("src_port", srcPort),
			slog.String("path", path),
			slog.String("query", query),
		)

		frame := parsedHTTP{
			Direction:  "read",
			Command:    method,
			Path:       path,
			Query:      query,
			Parameters: httpParameters(query),
			Payload:    append([]byte(nil), raw...),
		}
		if selenium.IsGridRequest(md.TargetPort, path) {
			if sess, ok := selenium.NewSessionRequest(method, path, body); ok {
				frame.Browser, frame.Binary, frame.Args, frame.Truncated = sess.Browser, sess.Binary, sess.Args, sess.Truncated
			}
		}
		server.events = append(server.events, frame)

		resp := server.buildResponse(ctx, method, uriRaw, path, body, md, log, hp)
		if resp != nil {
			if writeErr := server.write(resp); writeErr != nil {
				log.Debug("Failed to write HTTP response", slog.String("protocol", "http"), producer.ErrAttr(writeErr))
				endReason = connection.EndWriteError
				return nil
			}
		}

		if err != nil {
			log.Debug("Failed to read data", slog.String("protocol", "http"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
	}
	return nil
}
