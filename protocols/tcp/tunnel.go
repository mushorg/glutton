package tcp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/socks"
	"github.com/spf13/viper"
)

// tunnelFrame is one frame captured after a granted proxy CONNECT (SOCKS or
// HTTP CONNECT). Each handler maps it onto its own decoded frame type.
type tunnelFrame struct {
	Direction   string
	Command     string // tunnel or tls-clienthello on reads
	Status      string // tls-handshake on writes
	Path        string // CONNECT target (host:port), set on reads
	Payload     []byte
	PayloadHash string
	Truncated   bool
	Error       string               // why a tls-handshake write failed
	Hello       *helpers.ClientHello // on tls-clienthello reads
	Summary     *socks.HTTPSummary   // HTTP request volume on tunnel reads
	HTTP        []parsedHTTP         // what the HTTP handler decoded and replied in the tunnel
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

// tunnelRead stores data and builds its read frame.
func tunnelRead(path, command, protocol string, data []byte, truncated bool, hello *helpers.ClientHello, logger interfaces.Logger) tunnelFrame {
	if _, err := helpers.Store(data, "payloads"); err != nil {
		logger.Error("Failed to store tunneled payload", slog.String("protocol", protocol), producer.ErrAttr(err))
	}
	frame := tunnelFrame{
		Direction:   "read",
		Command:     command,
		Path:        path,
		Payload:     data,
		PayloadHash: helpers.SHA256Hex(data),
		Truncated:   truncated,
		Hello:       hello,
	}
	if command == "tunnel" {
		if sum, ok := socks.SummarizeHTTP(data); ok {
			frame.Summary = &sum
		}
	}
	return frame
}

// serveTunnelHTTP replays the captured tunnel bytes through the HTTP handler
// and returns its frames (requests and replies). Replies go to w; the canned
// judge reply answers what HTTP has no route for. The conn is not read again,
// so a flood past the capture cap is never served.
func serveTunnelHTTP(ctx context.Context, w net.Conn, data []byte, md *connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) ([]parsedHTTP, string) {
	md.AddInner("http")
	srv := newHTTPServer(&readerConn{Conn: w, r: bytes.NewReader(data)})
	srv.tunnel = true
	srv.tunnelReply = socks.TunnelHTTPReply()
	reason, _ := srv.serve(ctx, *md, logger, h)
	switch reason {
	case connection.EndWriteError, connection.EndTimeout:
		return srv.local, reason
	}
	return srv.local, connection.EndHandlerClose
}

// serveTunnel captures the first bytes after a granted CONNECT to path, read
// from r (conn's buffered reader). A complete TLS ClientHello is terminated
// with a self-signed cert matching the SNI (or CONNECT host) and tagged
// tls-clienthello with SNI/JA fingerprints; a following HTTP request gets a
// canned JSON judge reply. Plaintext HTTP in the tunnel gets the same reply,
// anything else none. Nothing is dialed or forwarded. Frames go to emit in
// wire order; md gets the TLS info and inner layers.
func serveTunnel(ctx context.Context, conn net.Conn, r io.Reader, path, protocol string, md *connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, emit func(tunnelFrame)) (endReason string, err error) {
	data, truncated, readErr := readTunnelBytes(r)
	if len(data) == 0 {
		return connection.EndReasonFromRead(readErr), readErr
	}

	if !truncated {
		if hello, ok := helpers.ParseClientHello(data); ok {
			emit(tunnelRead(path, "tls-clienthello", protocol, data, false, hello, logger))
			if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", protocol), producer.ErrAttr(err))
				return connection.EndTimeout, nil
			}
			cert, certErr := helpers.SelfSignedCertificateForHost(tunnelCertName(hello.SNI, path))
			if certErr != nil {
				logger.Error("Failed to build tunnel TLS certificate", slog.String("protocol", protocol), producer.ErrAttr(certErr))
				return connection.EndHandlerClose, nil
			}
			rec := &tcpWriteRecorder{Conn: conn, on: true}
			tlsConn, info, herr := helpers.TerminateTLSFromWith(cert, rec, io.MultiReader(bytes.NewReader(data), r))
			rec.on = false
			if rec.buf.Len() > 0 || rec.err != nil {
				frame := tunnelFrame{Direction: "write", Status: "tls-handshake", Error: writeErrorName(rec.err)}
				if rec.buf.Len() > 0 {
					frame.Payload = append([]byte(nil), rec.buf.Bytes()...)
					frame.PayloadHash = helpers.SHA256Hex(frame.Payload)
				}
				emit(frame)
			}
			if herr != nil {
				logger.Debug("TLS handshake failed", slog.String("protocol", protocol), producer.ErrAttr(herr))
				if rec.err != nil {
					return connection.EndWriteError, nil
				}
				return connection.EndReasonFromRead(herr), nil
			}
			md.TLS = info
			md.AddInner("tls")
			if err := h.UpdateConnectionTimeout(ctx, tlsConn); err != nil {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", protocol), producer.ErrAttr(err))
				return connection.EndTimeout, nil
			}
			plain, plainTrunc, plainErr := readTunnelBytes(tlsConn)
			if len(plain) == 0 {
				return connection.EndReasonFromRead(plainErr), nil
			}
			return emitTunnelData(ctx, tlsConn, path, protocol, plain, plainTrunc, md, logger, h, emit), nil
		}
	}
	return emitTunnelData(ctx, conn, path, protocol, data, truncated, md, logger, h, emit), nil
}

// emitTunnelData emits the tunnel read frame for data and answers it when it
// is a complete HTTP request.
func emitTunnelData(ctx context.Context, w net.Conn, path, protocol string, data []byte, truncated bool, md *connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, emit func(tunnelFrame)) string {
	frame := tunnelRead(path, "tunnel", protocol, data, truncated, nil, logger)
	reason := connection.EndHandlerClose
	if !truncated && socks.LooksLikeHTTPRequest(data) {
		frame.HTTP, reason = serveTunnelHTTP(ctx, w, data, md, logger, h)
	}
	emit(frame)
	return reason
}
