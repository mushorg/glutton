package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/socks"
	"github.com/spf13/viper"
)

type parsedSOCKS struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"` // socks4a-connect, socks5-greeting, socks5-auth, tunnel, tls-clienthello, ...
	Path        string `json:"path,omitempty"`    // requested host:port
	Status      string `json:"status,omitempty"`  // granted, rejected, no-auth, user-pass, no-acceptable-method, tls-handshake, 200 on writes
	Version     int    `json:"version,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	User        string `json:"user,omitempty"`     // SOCKS4 userid or RFC 1929 username
	Password    string `json:"password,omitempty"` // RFC 1929 password
	Methods     []int  `json:"methods,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	Error       string `json:"error,omitempty"` // why a tls-handshake write failed
	// HTTP request volume in a tunnel read: pipelined repeats are counted, not stored.
	Requests         int    `json:"requests,omitempty"`
	DistinctRequests int    `json:"distinct_requests,omitempty"`
	RequestLine      string `json:"request_line,omitempty"` // first request line
	UserAgent        string `json:"user_agent,omitempty"`
	// HTTP is what the HTTP handler decoded from a plaintext (or TLS-terminated)
	// tunnel read, including its replies; set instead of a socks write frame.
	HTTP []parsedHTTP `json:"http,omitempty"`
	// TLS ClientHello fingerprint fields on a tls-clienthello read.
	*helpers.ClientHello
}

type socksServer struct {
	events []parsedSOCKS
	conn   net.Conn
	r      *bufio.Reader
}

// socksBoundPort is the BND.PORT reported for a granted CONNECT; a var so
// tests are deterministic.
var socksBoundPort = func() uint16 {
	n, err := rand.Int(rand.Reader, big.NewInt(28232))
	if err != nil {
		return 40000
	}
	return uint16(32768 + n.Int64())
}

// socksHostWait is how long a SOCKS4a request may stall after the userid
// before it is granted without a hostname; a var so tests run instantly.
var socksHostWait = time.Second

// socksBoundIP is the BND.ADDR reported for a granted CONNECT. Always 0.0.0.0
// so the reply does not leak the sensor address (RFC 1928 allows an
// unspecified bind address; many proxies do the same). It never reflects the
// requested destination.
func socksBoundIP(_ net.Conn) net.IP {
	return net.IPv4zero
}

func (s *socksServer) captureRequest(req socks.Request) {
	frame := parsedSOCKS{
		Direction: "read",
		Version:   int(req.Version),
		User:      req.User,
		Payload:   req.Raw,
		Truncated: req.Truncated,
	}
	if req.Host != "" || req.Truncated {
		frame.Command = req.Name()
		frame.Host = req.Host
		frame.Port = int(req.Port)
		frame.Path = req.Addr()
	}
	s.events = append(s.events, frame)
}

func (s *socksServer) write(data []byte, command, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedSOCKS{
		Direction: "write",
		Command:   command,
		Status:    status,
		Payload:   data,
	})
	return nil
}

// readTunnelBytes reads up to max_tcp_payload from r. readErr is set only when
// nothing arrived.
func readTunnelBytes(r io.Reader) (data []byte, truncated bool, readErr error) {
	limit := viper.GetInt("max_tcp_payload")
	if limit <= 0 {
		limit = maxBufferSize
	}
	buffer := make([]byte, maxBufferSize)
	for {
		n, err := r.Read(buffer)
		data = append(data, buffer[:n]...)
		if len(data) > limit {
			data = data[:limit]
			truncated = true
			break
		}
		if err != nil {
			readErr = err
			break
		}
		if n < len(buffer) {
			break
		}
	}
	if len(data) == 0 {
		return nil, false, readErr
	}
	return data, truncated, nil
}

func (s *socksServer) captureTunnel(path, command string, data []byte, truncated bool, hello *helpers.ClientHello) error {
	_, storeErr := helpers.Store(data, "payloads")
	frame := parsedSOCKS{
		Direction:   "read",
		Command:     command,
		Path:        path,
		Payload:     data,
		PayloadHash: helpers.SHA256Hex(data),
		Truncated:   truncated,
		ClientHello: hello,
	}
	if command == "tunnel" {
		if sum, ok := socks.SummarizeHTTP(data); ok {
			frame.Requests = sum.Requests
			frame.DistinctRequests = sum.Distinct
			frame.RequestLine = sum.First
			frame.UserAgent = sum.UserAgent
		}
	}
	s.events = append(s.events, frame)
	return storeErr
}

// tunnelCertName picks the name for the tunnel TLS certificate: ClientHello
// SNI when present, otherwise the CONNECT host from path (host:port).
func tunnelCertName(sni, path string) string {
	if sni != "" {
		return sni
	}
	host, _, err := net.SplitHostPort(path)
	if err != nil {
		return ""
	}
	return host
}

// serveTunnelHTTP replays the captured tunnel bytes through the HTTP handler
// and attaches its frames (requests and replies) to the tunnel read frame just
// captured. Replies go to w; the canned judge reply answers what HTTP has no
// route for. The conn is not read again, so a flood past the capture cap is
// never served.
func (s *socksServer) serveTunnelHTTP(ctx context.Context, w net.Conn, data []byte, md *connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) string {
	md.AddInner("http")
	srv := newHTTPServer(&readerConn{Conn: w, r: bytes.NewReader(data)})
	srv.tunnel = true
	srv.tunnelReply = socks.TunnelHTTPReply()
	reason, _ := srv.serve(ctx, *md, logger, h)
	s.events[len(s.events)-1].HTTP = srv.local
	switch reason {
	case connection.EndWriteError, connection.EndTimeout:
		return reason
	}
	return connection.EndHandlerClose
}

// handleTunnel captures the first bytes after a granted CONNECT. A complete
// TLS ClientHello is terminated with a self-signed cert matching the SNI (or
// CONNECT host) and tagged tls-clienthello with SNI/JA fingerprints; a
// following HTTP request gets a canned JSON judge reply. Plaintext HTTP in
// the tunnel gets the same reply. Nothing is dialed or forwarded.
func (s *socksServer) handleTunnel(ctx context.Context, path string, md *connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (endReason string, err error) {
	data, truncated, readErr := readTunnelBytes(s.r)
	if len(data) == 0 {
		return connection.EndReasonFromRead(readErr), readErr
	}

	if !truncated {
		if hello, ok := helpers.ParseClientHello(data); ok {
			if storeErr := s.captureTunnel(path, "tls-clienthello", data, false, hello); storeErr != nil {
				logger.Error("Failed to store tunneled payload", slog.String("protocol", "socks"), producer.ErrAttr(storeErr))
			}
			if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", "socks"), producer.ErrAttr(err))
				return connection.EndTimeout, nil
			}
			cert, certErr := helpers.SelfSignedCertificateForHost(tunnelCertName(hello.SNI, path))
			if certErr != nil {
				logger.Error("Failed to build tunnel TLS certificate", slog.String("protocol", "socks"), producer.ErrAttr(certErr))
				return connection.EndHandlerClose, nil
			}
			rec := &tcpWriteRecorder{Conn: s.conn, on: true}
			tlsConn, info, herr := helpers.TerminateTLSFromWith(cert, rec, io.MultiReader(bytes.NewReader(data), s.r))
			rec.on = false
			if rec.buf.Len() > 0 || rec.err != nil {
				frame := parsedSOCKS{Direction: "write", Status: "tls-handshake", Error: writeErrorName(rec.err)}
				if rec.buf.Len() > 0 {
					frame.Payload = append([]byte(nil), rec.buf.Bytes()...)
					frame.PayloadHash = helpers.SHA256Hex(frame.Payload)
				}
				s.events = append(s.events, frame)
			}
			if herr != nil {
				logger.Debug("TLS handshake failed", slog.String("protocol", "socks"), producer.ErrAttr(herr))
				if rec.err != nil {
					return connection.EndWriteError, nil
				}
				return connection.EndReasonFromRead(herr), nil
			}
			md.TLS = info
			md.AddInner("tls")
			if err := h.UpdateConnectionTimeout(ctx, tlsConn); err != nil {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", "socks"), producer.ErrAttr(err))
				return connection.EndTimeout, nil
			}
			plain, plainTrunc, plainErr := readTunnelBytes(tlsConn)
			if len(plain) == 0 {
				return connection.EndReasonFromRead(plainErr), nil
			}
			if storeErr := s.captureTunnel(path, "tunnel", plain, plainTrunc, nil); storeErr != nil {
				logger.Error("Failed to store tunneled payload", slog.String("protocol", "socks"), producer.ErrAttr(storeErr))
			}
			if !plainTrunc && socks.LooksLikeHTTPRequest(plain) {
				return s.serveTunnelHTTP(ctx, tlsConn, plain, md, logger, h), nil
			}
			return connection.EndHandlerClose, nil
		}
	}

	if storeErr := s.captureTunnel(path, "tunnel", data, truncated, nil); storeErr != nil {
		logger.Error("Failed to store tunneled payload", slog.String("protocol", "socks"), producer.ErrAttr(storeErr))
	}
	if !truncated && socks.LooksLikeHTTPRequest(data) {
		return s.serveTunnelHTTP(ctx, s.conn, data, md, logger, h), nil
	}
	return connection.EndHandlerClose, nil
}

// HandleSOCKS answers SOCKS4, SOCKS4a and SOCKS5 proxy requests: it grants
// CONNECT without dialing anything, then answers a tunneled TLS/HTTP judge
// check with a canned reply (tunnel TLS cert matches SNI/CONNECT host).
// SOCKS5 clients offering username/password are asked for it.
func HandleSOCKS(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &socksServer{events: []parsedSOCKS{}, conn: conn, r: bufio.NewReader(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("socks", conn, md, helpers.FirstOrEmpty[parsedSOCKS](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "socks"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SOCKS connection", slog.String("protocol", "socks"), producer.ErrAttr(err))
		}
	}()

	// readFailed records a client read error as expected attacker behavior.
	readFailed := func(err error) error {
		logger.Debug("Failed to read data", slog.String("protocol", "socks"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	timeout := func() bool {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "socks"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return false
		}
		return true
	}
	writeFailed := func(err error) error {
		logger.Error("Failed to write to connection", slog.String("protocol", "socks"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	if !timeout() {
		return nil
	}
	version, err := socks.ReadVersion(server.r)
	if err != nil {
		return readFailed(err)
	}

	var req socks.Request
	switch version {
	case socks.Version4:
		// checkers sometimes send the SOCKS4a hostname in a later segment, or
		// never; bound the wait and answer the request we have
		if err := conn.SetReadDeadline(time.Now().Add(socksHostWait)); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "socks"), producer.ErrAttr(err))
		}
		req, err = socks.ReadSOCKS4(server.r)
		var netErr net.Error
		hostTimedOut := req.Truncated && errors.As(err, &netErr) && netErr.Timeout()
		if err != nil && !hostTimedOut {
			server.captureRequest(req)
			return readFailed(err)
		}
		if !timeout() {
			return nil
		}
		server.captureRequest(req)
		logSOCKSRequest(logger, conn, md, req)
		if req.Command != socks.CmdConnect {
			if err := server.write(socks.Reply4(socks.Reply4Rejected, nil, 0), req.Name(), "rejected"); err != nil {
				return writeFailed(err)
			}
			return nil
		}
		reply := socks.Reply4(socks.Reply4Granted, socksBoundIP(conn), socksBoundPort())
		if err := server.write(reply, req.Name(), "granted"); err != nil {
			return writeFailed(err)
		}

	case socks.Version5:
		greeting, err := socks.ReadGreeting(server.r)
		frame := parsedSOCKS{Direction: "read", Command: "socks5-greeting", Version: socks.Version5, Payload: greeting.Raw}
		for _, m := range greeting.Methods {
			frame.Methods = append(frame.Methods, int(m))
		}
		server.events = append(server.events, frame)
		if err != nil {
			return readFailed(err)
		}
		method := socks.SelectMethod(greeting.Methods)
		status := map[byte]string{
			socks.MethodNoAuth:       "no-auth",
			socks.MethodUserPass:     "user-pass",
			socks.MethodNoAcceptable: "no-acceptable-method",
		}[method]
		if err := server.write(socks.MethodReply(method), "socks5-greeting", status); err != nil {
			return writeFailed(err)
		}
		if method == socks.MethodNoAcceptable {
			return nil
		}

		if method == socks.MethodUserPass {
			if !timeout() {
				return nil
			}
			auth, err := socks.ReadAuth(server.r)
			server.events = append(server.events, parsedSOCKS{
				Direction: "read",
				Command:   "socks5-auth",
				Version:   socks.Version5,
				User:      auth.User,
				Password:  auth.Password,
				Payload:   auth.Raw,
			})
			if err != nil {
				return readFailed(err)
			}
			if err := server.write(socks.AuthReply(0x00), "socks5-auth", "granted"); err != nil {
				return writeFailed(err)
			}
		}

		if !timeout() {
			return nil
		}
		req, err = socks.ReadSOCKS5(server.r)
		server.captureRequest(req)
		if errors.Is(err, socks.ErrBadAddrType) {
			if err := server.write(socks.Reply5(socks.Reply5AddrNotSupported, nil, 0), req.Name(), "rejected"); err != nil {
				return writeFailed(err)
			}
			return nil
		}
		if err != nil {
			return readFailed(err)
		}
		logSOCKSRequest(logger, conn, md, req)
		if req.Command != socks.CmdConnect {
			if err := server.write(socks.Reply5(socks.Reply5CommandNotSupported, nil, 0), req.Name(), "rejected"); err != nil {
				return writeFailed(err)
			}
			return nil
		}
		reply := socks.Reply5(socks.Reply5Succeeded, socksBoundIP(conn), socksBoundPort())
		if err := server.write(reply, req.Name(), "granted"); err != nil {
			return writeFailed(err)
		}

	default:
		// not SOCKS: keep what arrived with the first byte and give up
		rest, _ := server.r.Peek(server.r.Buffered())
		data := append([]byte{version}, rest...)
		server.events = append(server.events, parsedSOCKS{Direction: "read", Payload: data})
		return nil
	}

	if !timeout() {
		return nil
	}
	reason, err := server.handleTunnel(ctx, req.Addr(), &md, logger, h)
	if reason != "" {
		endReason = reason
	}
	if err != nil {
		logger.Debug("Failed to read data", slog.String("protocol", "socks"), producer.ErrAttr(err))
	}
	return nil
}

func logSOCKSRequest(logger interfaces.Logger, conn net.Conn, md connection.Metadata, req socks.Request) {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	logger.Info(
		"SOCKS request",
		slog.String("handler", "socks"),
		slog.String("protocol", "socks"),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("command", req.Name()),
		slog.String("target", req.Addr()),
	)
}
