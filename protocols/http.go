package protocols

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
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

func handlePOST(req *http.Request, conn net.Conn, buf *bytes.Buffer, logger Logger) error {
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

// HandleHTTP takes a net.Conn and does basic HTTP communication
func HandleHTTP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Error("failed to close the HTTP connection", zap.Error(err))
		}
	}()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("failed to read the HTTP request: %w", err)
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to split the host: %w", err)
	}
	ck := freki.NewConnKeyByString(host, port)
	md := h.ConnectionByFlow(ck)

	logger.Info(
		fmt.Sprintf("HTTP %s request handled: %s", req.Method, req.URL.EscapedPath()),
		zap.String("handler", "http"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
		zap.String("path", req.URL.EscapedPath()),
		zap.String("method", req.Method),
		zap.String("query", req.URL.Query().Encode()),
	)

	var buf = &bytes.Buffer{}
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf = bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		length, err := buf.ReadFrom(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read the HTTP body: %w", err)
		}
		logger.Info(fmt.Sprintf("HTTP payload:\n%s", hex.Dump(buf.Bytes()[:length%1024])))
	}

	switch req.Method {
	case http.MethodPost:
		return handlePOST(req, conn, buf, logger)
	}

	if strings.Contains(req.RequestURI, "wallet") {
		logger.Info(
			"HTTP wallet request",
			zap.String("handler", "http"),
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
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send HTTP response: %w", err)
	}
	return nil
}
