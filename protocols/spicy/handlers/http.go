package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/protocols/tcp"
)

// Identical implementation of the original Go HTTP handler, but using Spicy for parsing
// I've tried to keep the logs and responses as close to the original as possible

func sendJSON(conn net.Conn, b []byte) error {
	_, err := conn.Write(
		append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(b))), b...),
	)
	return err
}

func writePlainOK(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return err
}

func handleEthereumRPC(body []byte, conn net.Conn) bool {
	if !bytes.Contains(body, []byte("eth_blockNumber")) {
		return false
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
	_ = sendJSON(conn, b)
	return true
}

func handleYarnNewApplication(method, uri string, conn net.Conn) bool {
	if method != "POST" || !strings.Contains(uri, "cluster/apps/new-application") {
		return false
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
	_ = sendJSON(conn, resp)
	return true
}

func handleWallet(uri string, conn net.Conn) bool {
	if !strings.Contains(uri, "wallet") {
		return false
	}
	body := []byte(`[[""]]`)
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(body))
	conn.Write([]byte(header))
	conn.Write(body)
	return true
}

func handleDockerAPIVersion(uri string, conn net.Conn, log interfaces.Logger) bool {
	if !strings.HasPrefix(uri, "/v1.16/version") {
		return false
	}
	data, err := tcp.Res.ReadFile("resources/docker_api.json")
	if err != nil {
		log.Error("failed to read docker_api.json", producer.ErrAttr(err))
		return false
	} else {
		conn.Write(append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n", len(data))), data...))
	}
	return true
}

func handleCitrixSMB(uri string, conn net.Conn) bool {
	if !strings.HasPrefix(uri, "/vpn/") {
		return false
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
	conn.Write([]byte("HTTP/1.1 200 OK\r\n" + headers + smbCfg))
	return true
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
	go func() {
		if err := tcp.HandleTCP(ctx, c, md, log, hp); err != nil {
			log.Error("vmware-send TCP relay error", producer.ErrAttr(err))
		}
	}()
	return true
}

func HandleHTTP(ctx context.Context, conn net.Conn, md connection.Metadata, log interfaces.Logger, hp interfaces.Honeypot) error {
	defer conn.Close()

	payload, err := spicy.ReadInitialBytes("http", conn)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}

	parsed, err := spicy.Parse("http", payload) // parse the HTTP request using Spicy
	if err != nil {
		log.Error("spicy parse error", producer.ErrAttr(err))
		_ = hp.ProduceTCP("spicy-http-failed", conn, md, payload,
			map[string]string{"error": err.Error()})
		return err
	}

	method, _ := parsed.Fields["method"].(string)
	uri, _ := parsed.Fields["uri"].(string)
	version, _ := parsed.Fields["version.number"].(string)

	method = strings.ToUpper(method)

	var body []byte
	if v, ok := parsed.Fields["body.content"]; ok {
		switch b := v.(type) {
		case []byte:
			body = b
		case string:
			body = []byte(b)
		}
	}

	path, query := uri, ""
	if sp := strings.SplitN(uri, "?", 2); len(sp) == 2 {
		path, query = sp[0], sp[1]
	}

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	log.Info(fmt.Sprintf("HTTP %s %s request handled: %s", version, method, path), // added "version" as a proof of concept, not identical to the original pure Go parser
		slog.String("handler", "spicy-http"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("path", path),
		slog.String("query", query),
	)

	if len(body) > 0 {
		max := len(body)
		if max > 1024 {
			max = 1024
		}
		log.Info("HTTP payload:\n" + hex.Dump(body[:max]))
	}

	_ = hp.ProduceTCP("http", conn, md, payload, parsed)

	handled := false
	switch method {
	case "POST":
		handled = handleEthereumRPC(body, conn) || handleYarnNewApplication(method, uri, conn)
	}

	handled = handled || handleWallet(uri, conn) || handleDockerAPIVersion(uri, conn, log) || handleCitrixSMB(uri, conn) || handleVMwareSend(ctx, body, uri, md, log, hp)

	if !handled {
		_ = writePlainOK(conn)
	}
	return nil
}
