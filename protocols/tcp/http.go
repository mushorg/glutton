package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxHTTPRequests   = 50
	maxHTTPBody       = 1 << 20 // 1 MiB
	httpSessionCookie = "session"
)

var httpSessions = newSessionTable[parsedHTTP]()

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

// scanning attempts for CVE-2019-19781
// based on https://github.com/x1sec/citrix-honeypot/
func smbHandler(_ *http.Request) []byte {
	headers := `Server: Apache
X-Frame-Options: SAMEORIGIN
Last-Modified: Thu, 28 Nov 2019 20:19:22 GMT
ETag: "53-5986dd42b0680"
Accept-Ranges: bytes
Content-Length: 93
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: text/plain; charset=UTF-8`

	smbConfig := "\r\n\r\n[global]\r\n\tencrypt passwords = yes\r\n\tname resolve order = lmhosts wins host bcast\r\n"
	return []byte("HTTP/1.1 200 OK\r\n" + headers + smbConfig)
}

type parsedHTTP struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // HTTP method
	Path      string `json:"path,omitempty"`
	Query     string `json:"query,omitempty"`
	Host      string `json:"host,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Status    string `json:"status,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Payload   []byte `json:"payload,omitempty"` // raw HTTP request or response bytes
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
}

func newHTTPServer(conn net.Conn) *httpServer {
	srcHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &httpServer{
		sessionTracker: sessionTracker[parsedHTTP]{
			local:   []parsedHTTP{},
			srcHost: srcHost,
			table:   httpSessions,
			spec: sessionSpec[parsedHTTP]{
				protocol: "http",
				payload:  httpPayload,
				stamp:    stampHTTP,
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
	query := req.URL.Query().Encode()
	body, _ := io.ReadAll(req.Body)

	if c, err := req.Cookie(httpSessionCookie); err == nil && strings.TrimSpace(c.Value) != "" {
		s.bind(strings.TrimSpace(c.Value))
	} else {
		s.ensure()
	}

	s.record(parsedHTTP{
		Direction: "read",
		Command:   req.Method,
		Path:      path,
		Query:     query,
		Host:      req.Host,
		UserAgent: req.UserAgent(),
		Payload:   raw,
	})

	if len(body) > 0 {
		n := len(body)
		if n > 1024 {
			n = 1024
		}
		logger.Info(fmt.Sprintf("HTTP payload:\n%s", hex.Dump(body[:n])))
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

	if strings.HasPrefix(req.RequestURI, "/vpn/") {
		return s.write(smbHandler(req))
	}

	// Handler for VMWare Attack
	if strings.Contains(req.RequestURI, "hyper/send") {
		parts := strings.Split(string(body), " ")
		if len(parts) >= 11 {
			vconn, err := net.Dial("tcp", parts[9]+":"+parts[10])
			if err != nil {
				return err
			}
			go func() {
				if err := HandleTCP(ctx, vconn, md, logger, h); err != nil {
					logger.Error("Failed to handle vmware attack", producer.ErrAttr(err))
				}
			}()
		}
	}
	if err := s.write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err != nil {
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
	server.md = md
	server.logger = logger
	server.h = h

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

	srcHost, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxHTTPRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "http"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		raw, err := readHTTPMessage(server.bufin, maxHTTPBody)
		if len(raw) > 0 {
			req, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
			if parseErr != nil {
				logger.Debug("Failed to read the HTTP request", slog.String("protocol", "http"), producer.ErrAttr(parseErr))
				server.record(parsedHTTP{Direction: "read", Payload: append([]byte(nil), raw...)})
				endReason = connection.EndReadError
				break
			}

			if i == 0 && IsMCPPath(req.URL.EscapedPath()) {
				handoff = true
				return HandleMCP(ctx, PrependConn(conn, raw), md, logger, h)
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

			if handleErr := server.handleRequest(ctx, req, raw, md, logger, h); handleErr != nil {
				logger.Debug("Failed to handle HTTP request", slog.String("protocol", "http"), producer.ErrAttr(handleErr))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "http"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
	}
	return nil
}
