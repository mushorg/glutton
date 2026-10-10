package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/socks"
	"github.com/spf13/viper"
)

type parsedSOCKS struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"` // socks4a-connect, socks5-greeting, socks5-auth, tunnel, ...
	Path        string `json:"path,omitempty"`    // requested host:port
	Status      string `json:"status,omitempty"`  // granted, rejected, no-auth, user-pass, no-acceptable-method on writes
	Version     int    `json:"version,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	User        string `json:"user,omitempty"` // SOCKS4 userid or RFC 1929 username; passwords are never kept
	Methods     []int  `json:"methods,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
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

// socksBoundIP reports the sensor address as BND.ADDR, like a proxy whose
// outbound connections leave from the same host. It never reflects the
// requested destination.
func socksBoundIP(conn net.Conn) net.IP {
	if conn == nil || conn.LocalAddr() == nil {
		return net.IPv4zero
	}
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return net.IPv4zero
	}
	if ip := net.ParseIP(host).To4(); ip != nil {
		return ip
	}
	return net.IPv4zero
}

func (s *socksServer) captureRequest(req socks.Request) {
	frame := parsedSOCKS{
		Direction: "read",
		Version:   int(req.Version),
		User:      req.User,
		Payload:   req.Raw,
	}
	if req.Host != "" {
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

// readTunnel captures what the client sends through a granted tunnel, up to
// max_tcp_payload. Nothing is forwarded. readErr is set only when nothing
// arrived.
func (s *socksServer) readTunnel(path string) (readErr, storeErr error) {
	limit := viper.GetInt("max_tcp_payload")
	if limit <= 0 {
		limit = maxBufferSize
	}
	data := []byte{}
	buffer := make([]byte, maxBufferSize)
	truncated := false
	for {
		n, err := s.r.Read(buffer)
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
		return readErr, nil
	}
	// Store returns an empty hash for a payload it already has
	_, storeErr = helpers.Store(data, "payloads")
	s.events = append(s.events, parsedSOCKS{
		Direction:   "read",
		Command:     "tunnel",
		Path:        path,
		Payload:     data,
		PayloadHash: helpers.SHA256Hex(data),
		Truncated:   truncated,
	})
	return nil, storeErr
}

// HandleSOCKS answers SOCKS4, SOCKS4a and SOCKS5 proxy requests: it grants
// CONNECT without dialing anything, captures the first tunneled request and
// closes. SOCKS5 clients offering username/password are asked for it.
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
		if req, err = socks.ReadSOCKS4(server.r); err != nil {
			server.captureRequest(req)
			return readFailed(err)
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
	readErr, storeErr := server.readTunnel(req.Addr())
	if storeErr != nil {
		logger.Error("Failed to store tunneled payload", slog.String("protocol", "socks"), producer.ErrAttr(storeErr))
	}
	if readErr != nil {
		return readFailed(readErr)
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
