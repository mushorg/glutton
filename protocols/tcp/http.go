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
	"github.com/mushorg/glutton/protocols/interfaces"
)

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

func sendJSON(data []byte, conn net.Conn) error {
	_, err := conn.Write(append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(data))), data...))
	return err
}

func handlePOST(req *http.Request, conn net.Conn, buf *bytes.Buffer, logger interfaces.Logger) error {
	body := buf.Bytes()
	// Ethereum RPC call
	if strings.Contains(string(body), "eth_blockNumber") {
		data, err := handleEthereumRPC(body)
		if err != nil {
			return err
		}
		return sendJSON(data, conn)
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
			return err
		}
		logger.Info("sending hadoop yarn hack response")
		return sendJSON(resp, conn)
	}
	return nil
}

// scanning attempts for CVE-2019-19781
// based on https://github.com/x1sec/citrix-honeypot/
func smbHandler(conn net.Conn, _ *http.Request) error {
	// if strings.ContainsRune(r.URL.RawPath, '%') {
	// with IDS evasion."
	// }

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
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n" + headers + smbConfig))
	return err
}

type decodedHTTP struct {
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
}

// HandleHTTP takes a net.Conn and does basic HTTP communication
func HandleHTTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Error("Failed to close the HTTP connection", producer.ErrAttr(err))
		}
	}()

	reader := bufio.NewReader(conn)
	preface, err := reader.Peek(24)
	if err != nil {
		if err == io.EOF {
			logger.Debug("Client disconneted early")
			return nil
		}
		return fmt.Errorf("failed to peek HTTP/2 preface: %w", err)
	}
	if bytes.Equal(preface, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		settingsFrame := []byte("\x00\x00\x00\x04\x00\x00\x00\x00\x00")
		if _, err := conn.Write(settingsFrame); err != nil {
			logger.Error("Failed to write HTTP/2 response", slog.String("error", err.Error()))
		}
		return conn.Close()
	}

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("failed to read the HTTP request: %w", err)
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to split the host: %w", err)
	}

	logger.Info(
		fmt.Sprintf("HTTP %s request handled: %s", req.Method, req.URL.EscapedPath()),
		slog.String("handler", "http"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("path", req.URL.EscapedPath()),
		slog.String("method", req.Method),
		slog.String("query", req.URL.Query().Encode()),
	)

	buf := &bytes.Buffer{}
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf = bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		length, err := buf.ReadFrom(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read the HTTP body: %w", err)
		}
		logger.Info(fmt.Sprintf("HTTP payload:\n%s", hex.Dump(buf.Bytes()[:length%1024])))
	}

	if err := h.ProduceTCP("http", conn, md, buf.Bytes(), decodedHTTP{
		Method: req.Method,
		URL:    req.URL.EscapedPath(),
		Path:   req.URL.EscapedPath(),
		Query:  req.URL.Query().Encode(),
	}); err != nil {
		logger.Error("Failed to produce message", slog.String("protocol", "http"), producer.ErrAttr(err))
	}

	switch req.Method {
	case http.MethodPost:
		return handlePOST(req, conn, buf, logger)
	}

	if strings.Contains(req.RequestURI, "wallet") {
		logger.Info(
			"HTTP wallet request",
			slog.String("handler", "http"),
		)
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length:20\r\n\r\n[[\"\"]]\r\n\r\n"))
		return err
	}

	if strings.Contains(req.RequestURI, "/v1.16/version") {
		data, err := res.ReadFile("resources/docker_api.json")
		if err != nil {
			return fmt.Errorf("failed to read embedded file: %w", err)
		}
		_, err = conn.Write(append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(data))), data...))
		return err
	}

	if strings.HasPrefix(req.RequestURI, "/vpn/") {
		return smbHandler(conn, req)
	}

	// Handler for VMWare Attack
	if strings.Contains(req.RequestURI, "hyper/send") {
		body := string(buf.Bytes()[:])
		parts := strings.Split(body, " ")
		if len(parts) >= 11 {
			conn, err := net.Dial("tcp", parts[9]+":"+parts[10])
			if err != nil {
				return err
			}
			go func() {
				if err := HandleTCP(ctx, conn, md, logger, h); err != nil {
					logger.Error("Failed to handle vmware attack", producer.ErrAttr(err))
				}
			}()
		}
	}
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send HTTP response: %w", err)
	}
	return nil
}
