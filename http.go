package glutton

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
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

// HandleHTTP takes a net.Conn and does basic HTTP communication
func (g *Glutton) HandleHTTP(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[http    ] error: %v", err))
		}
	}()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		g.logger.Error(fmt.Sprintf("[http    ] error: %v", err))
		return err
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		g.logger.Error(fmt.Sprintf("[http    ] error: %v", err))
	}
	ck := freki.NewConnKeyByString(host, port)
	md := g.processor.Connections.GetByFlow(ck)

	g.logger.Info(
		fmt.Sprintf("HTTP %s request handled: %s", req.Method, req.URL.EscapedPath()),
		zap.String("handler", "http"),
		zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		zap.String("src_ip", host),
		zap.String("src_port", port),
		zap.String("path", req.URL.EscapedPath()),
		zap.String("method", req.Method),
		zap.String("query", req.URL.Query().Encode()),
	)
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf := bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		if _, err = buf.ReadFrom(req.Body); err != nil {
			g.logger.Error(fmt.Sprintf("[http    ] error: %v", err))
			return err
		}
		body := buf.Bytes()
		g.logger.Info(
			"HTTP body payload",
			zap.String("handler", "http"),
			zap.String("payload_hex", hex.EncodeToString(body[:])),
		)
	}
	if strings.Contains(req.RequestURI, "wallet") {
		g.logger.Info(
			"HTTP wallet request",
			zap.String("handler", "http"),
		)
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length:20\r\n\r\n[[\"\"]]\r\n\r\n"))
		return err
	}
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return err
}
