package tcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/banners"
	"github.com/mushorg/glutton/protocols/tcp/rfb"

	"github.com/spf13/viper"
)

type parsedTCP struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"` // matched payload signature on reads
	Status      string `json:"status,omitempty"`  // canned response name, or "random", on writes
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	// TLS ClientHello fingerprint fields (tls_version, ja3, ja4, ...) on a
	// tls-clienthello or tls-alert read, flattened into the frame.
	*helpers.ClientHello
}

const (
	// tlsAlert is the banners response name for a TLS record the catch-all
	// cannot terminate: it is answered with a handshake_failure alert.
	tlsAlert = "tls-alert"
	// tlsClientHello tags a complete ClientHello the catch-all terminated.
	tlsClientHello = "tls-clienthello"
	// maxExchanges caps the client messages the catch-all answers on one
	// connection (a TLS ClientHello does not count).
	maxExchanges = 4
)

type tcpServer struct {
	events []parsedTCP
	conn   net.Conn
}

func randomReply() ([]byte, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(500))
	if err != nil {
		return nil, err
	}
	randomBytes := make([]byte, 12+randomInt.Int64())
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func (s *tcpServer) write(data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedTCP{
		Direction:   "write",
		Status:      status,
		PayloadHash: helpers.SHA256Hex(data),
		Payload:     data,
	})
	return nil
}

func (s *tcpServer) captureRead(data []byte, payloadHash, command string, hello *helpers.ClientHello) {
	s.events = append(s.events, parsedTCP{
		Direction:   "read",
		Command:     command,
		PayloadHash: payloadHash,
		Payload:     data,
		ClientHello: hello,
	})
}

// readPayload reads one client message: until a short read, a read error, or
// the max_tcp_payload cap. endReason is set when the read ended the session;
// err is only returned when the connection timeout could not be set.
func (s *tcpServer) readPayload(ctx context.Context, h interfaces.Honeypot, logger interfaces.Logger) (data []byte, endReason string, err error) {
	buffer := make([]byte, maxBufferSize)
	for {
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			return data, connection.EndTimeout, err
		}
		n, err := s.conn.Read(buffer)
		if err != nil {
			logger.Debug("read error", slog.String("handler", "tcp"), producer.ErrAttr(err))
			return data, connection.EndReasonFromRead(err), nil
		}
		data = append(data, buffer[:n]...)
		if n < maxBufferSize {
			return data, "", nil
		}
		if len(data) > viper.GetInt("max_tcp_payload") {
			logger.Debug("max message length reached", slog.String("handler", "tcp"))
			return data, connection.EndMaxFrames, nil
		}
	}
}

// bannerFollowUp answers the client's reply to a server-first banner so the
// handshake goes one step further instead of getting random bytes. An RFB
// ProtocolVersion gets the security handshake the rfb handler would send.
func bannerFollowUp(banner banners.Response, data []byte) (banners.Response, bool) {
	if banner.Name != "rfb" {
		return banners.Response{}, false
	}
	version, ok := rfb.ParseVersion(data)
	if !ok {
		return banners.Response{}, false
	}
	if version == rfb.Version33 {
		return banners.Response{Name: "rfb-security", Data: rfb.SecurityType33(rfb.SecurityVNCAuth)}, true
	}
	return banners.Response{Name: "rfb-security", Data: rfb.SecurityTypes(rfbOffered...)}, true
}

// HasServerBanner reports whether the catch-all greets clients on port before
// they send anything, so dispatch must not wait for client bytes.
func HasServerBanner(port uint16) bool {
	resp, ok := banners.ForPort(port)
	return ok && resp.ServerFirst
}

// GreetsWhenIdle reports whether the catch-all greets clients on port that
// stay silent for a short wait; dispatch waits for client bytes and calls
// HandleTCPSilent if none arrive.
func GreetsWhenIdle(port uint16) bool {
	resp, ok := banners.ForPort(port)
	return ok && resp.GreetWhenIdle
}

// Handoff offers a session the catch-all decrypted in-band to another
// handler. It returns the connection to keep serving on (it may hold client
// bytes it peeked) and whether it took the session; a handler that takes it
// produces the event and closes the connection itself.
type Handoff func(ctx context.Context, conn net.Conn, md connection.Metadata) (net.Conn, bool, error)

// Options adjusts HandleTCPWith.
type Options struct {
	// Silent is set when the client stayed silent through the dispatch wait:
	// greet-when-idle ports send their banner before reading.
	Silent bool
	// AfterTLS, if set, is offered the decrypted session after an in-band
	// TLS handshake, so a protocol inside the tunnel (HTTPS) reaches its
	// handler instead of the catch-all replies.
	AfterTLS Handoff
}

// HandleTCP takes a net.Conn, captures what the client sends and answers with
// a canned service response (by payload signature, then destination port),
// falling back to random bytes, for up to maxExchanges client messages.
// Server-first ports get their banner on connect.
func HandleTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleTCP(ctx, conn, md, logger, h, Options{})
}

// HandleTCPSilent is HandleTCP for a client that stayed silent through the
// dispatch wait: greet-when-idle ports send their banner before reading.
func HandleTCPSilent(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleTCP(ctx, conn, md, logger, h, Options{Silent: true})
}

// HandleTCPWith is HandleTCP with options set by the catch-all dispatcher.
func HandleTCPWith(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, opts Options) error {
	return handleTCP(ctx, conn, md, logger, h, opts)
}

func handleTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, opts Options) error {
	silent := opts.Silent
	server := tcpServer{
		events: []parsedTCP{},
		conn:   conn,
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("faild to split remote address: %w", err)
	}

	endReason := connection.EndHandlerClose
	handoff := false
	defer func() {
		if handoff {
			return
		}
		md.EndReason = endReason
		if err := h.ProduceTCP("tcp", conn, md, helpers.FirstOrEmpty(server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "tcp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close TCP connection", slog.String("handler", "tcp"), producer.ErrAttr(err))
		}
	}()

	// greet sends a server-first banner; false means the session is over.
	greet := func(banner banners.Response) (bool, error) {
		if err := h.UpdateConnectionTimeout(ctx, server.conn); err != nil {
			endReason = connection.EndTimeout
			return false, err
		}
		if err := server.write(banner.Data, banner.Name); err != nil {
			logger.Debug("Failed to write banner", slog.String("protocol", "tcp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return false, nil
		}
		return true, nil
	}
	// read reads the next client message; a nil result means the session is over.
	read := func() ([]byte, error) {
		data, reason, err := server.readPayload(ctx, h, logger)
		if reason != "" {
			endReason = reason
		}
		if err != nil || len(data) == 0 {
			return nil, err
		}
		return data, nil
	}

	portResp, hasPortResp := banners.ForPort(md.TargetPort)
	greeted := hasPortResp && (portResp.ServerFirst || (silent && portResp.GreetWhenIdle))
	if greeted {
		if ok, err := greet(portResp); !ok {
			return err
		}
	}

	data, err := read()
	if data == nil {
		return err
	}
	payloadHash := server.storeRead(data, host, port, md, logger)

	// A complete ClientHello on a port without a tls: rule: finish the
	// handshake and answer what the client sends inside the tunnel, as on a
	// plaintext connection, instead of ending the session with an alert.
	if sigResp, matched := banners.ForPayload(data); matched && sigResp.Name == tlsAlert {
		if hello, ok := helpers.ParseClientHello(data); ok {
			server.captureRead(data, payloadHash, tlsClientHello, hello)
			if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
				endReason = connection.EndTimeout
				return err
			}
			tlsConn, info, err := helpers.TerminateTLSFrom(conn, io.MultiReader(bytes.NewReader(data), conn))
			if err != nil {
				logger.Debug("TLS handshake failed", slog.String("protocol", "tcp"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
			md.TLS = info
			server.conn = tlsConn

			greeted = hasPortResp && portResp.ServerFirst
			if greeted {
				if ok, err := greet(portResp); !ok {
					return err
				}
			} else if opts.AfterTLS != nil {
				// the next handler's event carries the handshake in its tls
				// object, so the ClientHello frame is not needed there
				next, took, err := opts.AfterTLS(ctx, server.conn, md)
				if took {
					handoff = true
					return err
				}
				server.conn = next
			}
			if data, err = read(); data == nil {
				return err
			}
			payloadHash = server.storeRead(data, host, port, md, logger)
		}
	}

	// Answer up to maxExchanges client messages, so a client that follows up
	// on the first reply gets another one instead of a closed connection.
	for round := 1; ; round++ {
		sigResp, matched := banners.ForPayload(data)
		command := ""
		if matched {
			command = sigResp.Name
		} else if greeted && round == 1 {
			// only the message right after the greeting answers it
			if sigResp, matched = bannerFollowUp(portResp, data); matched {
				command = portResp.Name
			}
		}
		var hello *helpers.ClientHello
		if command == tlsAlert {
			hello, _ = helpers.ParseClientHello(data)
		}
		server.captureRead(data, payloadHash, command, hello)

		resp := sigResp
		switch {
		case matched:
		case hasPortResp && !greeted:
			resp = portResp
		default:
			if resp.Data, err = randomReply(); err != nil {
				logger.Error("Failed to generate random reply", slog.String("handler", "tcp"), producer.ErrAttr(err))
				return nil
			}
			resp.Name = "random"
		}
		if resp.Silent {
			return nil
		}
		if err := server.write(resp.Data, resp.Name); err != nil {
			logger.Error("write error", slog.String("handler", "tcp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if resp.Close {
			return nil
		}
		if round == maxExchanges {
			logger.Debug("max exchanges reached", slog.String("handler", "tcp"))
			endReason = connection.EndMaxFrames
			return nil
		}
		if data, err = read(); data == nil {
			return err
		}
		payloadHash = server.storeRead(data, host, port, md, logger)
	}
}

// storeRead stores a client message as a payload sample and logs its arrival.
func (s *tcpServer) storeRead(data []byte, host, port string, md connection.Metadata, logger interfaces.Logger) string {
	payloadHash, err := helpers.Store(data, "payloads")
	if err != nil {
		logger.Error("Failed to store payload", slog.String("handler", "tcp"), producer.ErrAttr(err))
	}
	logger.Info(
		"Packet got handled by TCP handler",
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("handler", "tcp"),
		slog.String("payload_hash", payloadHash),
		slog.Bool("tls", md.TLS != nil),
	)
	return payloadHash
}
