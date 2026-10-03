package udp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/spf13/viper"
)

const proxyUDPHandler = "proxy_udp"

type proxyEvent struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

type proxyCapture struct {
	payload []byte
	bytes   int64
}

type udpFlow struct {
	key         string
	conn        *net.UDPConn
	srcAddr     *net.UDPAddr
	dstAddr     *net.UDPAddr
	md          connection.Metadata
	logger      interfaces.Logger
	h           interfaces.Honeypot
	idleTimeout time.Duration
	payloadSize int
	capture     bool

	mu       sync.Mutex
	readCap  proxyCapture
	writeCap proxyCapture
	closed   bool
}

type udpFlowTable struct {
	mu    sync.Mutex
	flows map[string]*udpFlow
}

var proxyUDPFlows = &udpFlowTable{flows: make(map[string]*udpFlow)}

func flowKey(srcAddr, dstAddr *net.UDPAddr) string {
	return srcAddr.String() + "->" + dstAddr.String()
}

func proxyUDPLogAttrs(fields ...any) []any {
	return append([]any{slog.String("handler", proxyUDPHandler)}, fields...)
}

func (c *proxyCapture) store(data []byte, max int) {
	c.bytes += int64(len(data))
	if max <= 0 || len(c.payload) >= max {
		return
	}
	remaining := max - len(c.payload)
	if len(data) > remaining {
		data = data[:remaining]
	}
	c.payload = append(c.payload, data...)
}

func (c *proxyCapture) event(direction string) *proxyEvent {
	if len(c.payload) == 0 {
		return nil
	}
	payload := append([]byte(nil), c.payload...)
	hash := sha256.Sum256(payload)
	return &proxyEvent{
		Direction:   direction,
		Payload:     payload,
		PayloadHash: fmt.Sprintf("%x", hash[:]),
		Bytes:       c.bytes,
		Truncated:   c.bytes > int64(len(payload)),
	}
}

func (t *udpFlowTable) get(key string) *udpFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flows[key]
}

func (t *udpFlowTable) remove(key string, expected *udpFlow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.flows[key]; ok && current == expected {
		delete(t.flows, key)
	}
}

func (f *udpFlow) refreshDeadline() {
	if f.idleTimeout <= 0 {
		_ = f.conn.SetReadDeadline(time.Time{})
		return
	}
	_ = f.conn.SetReadDeadline(time.Now().Add(f.idleTimeout))
}

func (f *udpFlow) capturePayload(direction string, data []byte) {
	if !f.capture || len(data) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch direction {
	case "read":
		f.readCap.store(data, f.payloadSize)
	case "write":
		f.writeCap.store(data, f.payloadSize)
	}
}

func (f *udpFlow) closeAndProduce() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	var events []proxyEvent
	if f.capture {
		if ev := f.readCap.event("read"); ev != nil {
			events = append(events, *ev)
		}
		if ev := f.writeCap.event("write"); ev != nil {
			events = append(events, *ev)
		}
	}
	f.mu.Unlock()

	proxyUDPFlows.remove(f.key, f)
	_ = f.conn.Close()

	payload := helpers.FirstOrEmpty(events).Payload
	if err := f.h.ProduceUDP(proxyUDPHandler, f.srcAddr, f.dstAddr, f.md, payload, events); err != nil {
		f.logger.Error("failed to produce proxy_udp message", proxyUDPLogAttrs(
			slog.String("function", "closeAndProduce"),
			producer.ErrAttr(err),
		)...)
	}
}

func (f *udpFlow) readLoop(ctx context.Context) {
	defer f.closeAndProduce()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = f.conn.Close()
		case <-stop:
		}
	}()

	buf := make([]byte, 65535)
	for {
		f.refreshDeadline()
		n, err := f.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				f.logger.Debug("proxy_udp flow idle timeout", proxyUDPLogAttrs(
					slog.String("function", "readLoop"),
					slog.String("source", f.srcAddr.String()),
					slog.String("target", f.conn.RemoteAddr().String()),
				)...)
				return
			}
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
				f.logger.Debug("proxy_udp upstream read ended", proxyUDPLogAttrs(
					slog.String("function", "readLoop"),
					producer.ErrAttr(err),
				)...)
			}
			return
		}
		if n == 0 {
			continue
		}

		resp := append([]byte(nil), buf[:n]...)
		f.capturePayload("write", resp)
		if err := f.h.ReplyUDP(f.srcAddr, f.dstAddr, resp); err != nil {
			f.logger.Debug("failed to reply proxy_udp payload", proxyUDPLogAttrs(
				slog.String("function", "readLoop"),
				producer.ErrAttr(err),
			)...)
			return
		}
	}
}

func dialProxyUDP(ctx context.Context, destAddr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: time.Duration(viper.GetInt("dial_timeout")) * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected udp dial type %T", conn)
	}
	return udpConn, nil
}

func getOrCreateFlow(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (*udpFlow, error) {
	key := flowKey(srcAddr, dstAddr)
	if existing := proxyUDPFlows.get(key); existing != nil {
		return existing, nil
	}

	destAddr := md.Rule.ProxyTarget.DialAddress
	conn, err := dialProxyUDP(ctx, destAddr)
	if err != nil {
		return nil, err
	}

	flow := &udpFlow{
		key:         key,
		conn:        conn,
		srcAddr:     srcAddr,
		dstAddr:     dstAddr,
		md:          md,
		logger:      logger,
		h:           h,
		idleTimeout: time.Duration(viper.GetInt("conn_timeout")) * time.Second,
		payloadSize: viper.GetInt("max_tcp_payload"),
		capture:     viper.GetBool("capture_traffic.enabled"),
	}

	proxyUDPFlows.mu.Lock()
	if existing := proxyUDPFlows.flows[key]; existing != nil {
		proxyUDPFlows.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	proxyUDPFlows.flows[key] = flow
	proxyUDPFlows.mu.Unlock()

	go flow.readLoop(ctx)
	logger.Debug("started proxy_udp flow", proxyUDPLogAttrs(
		slog.String("function", "getOrCreateFlow"),
		slog.String("source", srcAddr.String()),
		slog.String("target", destAddr),
		slog.Duration("idle_timeout", flow.idleTimeout),
	)...)
	return flow, nil
}

// HandleProxyUDP forwards UDP datagrams for a matched proxy_udp rule to an upstream
// host:port, maintaining a short-lived flow so multi-packet protocols (e.g. QUIC) work.
func HandleProxyUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	if srcAddr == nil || dstAddr == nil {
		logger.Error("missing proxy_udp addresses", proxyUDPLogAttrs(
			slog.String("function", "HandleProxyUDP"),
		)...)
		return nil
	}
	if md.Rule == nil {
		logger.Error("missing proxy_udp rule metadata", proxyUDPLogAttrs(
			slog.String("function", "HandleProxyUDP"),
		)...)
		return nil
	}
	if md.Rule.ProxyTarget == nil || md.Rule.ProxyTarget.DialAddress == "" {
		logger.Error("missing proxy_udp target metadata", proxyUDPLogAttrs(
			slog.String("function", "HandleProxyUDP"),
		)...)
		return nil
	}

	flow, err := getOrCreateFlow(ctx, srcAddr, dstAddr, md, logger, h)
	if err != nil {
		logger.Error("failed to connect to the target", proxyUDPLogAttrs(
			slog.String("function", "HandleProxyUDP"),
			slog.String("target", md.Rule.ProxyTarget.DialAddress),
			producer.ErrAttr(err),
		)...)
		return nil
	}

	flow.capturePayload("read", data)
	flow.refreshDeadline()
	if _, err := flow.conn.Write(data); err != nil {
		logger.Debug("failed to write proxy_udp payload", proxyUDPLogAttrs(
			slog.String("function", "HandleProxyUDP"),
			producer.ErrAttr(err),
		)...)
		flow.closeAndProduce()
		return nil
	}
	return nil
}
