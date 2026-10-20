package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mushorg/glutton/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type CKey [2]uint64

func newConnKey(clientAddr gopacket.Endpoint, clientPort gopacket.Endpoint) (CKey, error) {
	if clientAddr.EndpointType() != layers.EndpointIPv4 {
		return CKey{}, errors.New("clientAddr endpoint must be of type layers.EndpointIPv4")
	}

	if clientPort.EndpointType() != layers.EndpointTCPPort {
		return CKey{}, errors.New("clientPort endpoint must be of type layers.EndpointTCPPort")
	}

	return CKey{clientAddr.FastHash(), clientPort.FastHash()}, nil
}

func NewConnKeyByString(host, port string) (CKey, error) {
	clientAddr := layers.NewIPEndpoint(net.ParseIP(host).To4())
	p, err := strconv.Atoi(port)
	if err != nil {
		return CKey{}, err
	}
	clientPort := layers.NewTCPPortEndpoint(layers.TCPPort(p))
	return newConnKey(clientAddr, clientPort)
}

func NewConnKeyFromNetConn(conn net.Conn) (CKey, error) {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return NewConnKeyByString(host, port)
}

const (
	EndClientClose = "client_close"
	// EndClientReset marks a session the client aborted with a TCP RST.
	EndClientReset  = "client_reset"
	EndTimeout      = "timeout"
	EndHandlerClose = "handler_close"
	EndReadError    = "read_error"
	EndWriteError   = "write_error"
	EndMaxFrames    = "max_frames"
	// EndEvicted marks a session flushed early because its handler's session
	// table was full.
	EndEvicted = "evicted"
)

// EndReasonFromRead maps a read/timeout error to an event endReason.
func EndReasonFromRead(err error) string {
	if err == nil {
		return EndClientClose
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return EndTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return EndClientClose
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return EndClientReset
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return EndTimeout
	}
	return EndReadError
}

type Metadata struct {
	Added      time.Time
	Rule       *rules.Rule
	TargetPort uint16
	TargetIP   string
	EndReason  string
	// Fleet is a behavioral label the handler gave the session (e.g.
	// "ssh-authkeys-implant"); the producer uses it as the scanner when no
	// network or payload classification applies.
	Fleet string
	// TLS is set when the sensor terminated TLS (rule option tls) before the handler.
	TLS *TLSInfo
	// Outer lists protocol layers a wrapper peeled off before the handler ran
	// (e.g. "tls"), outermost first.
	Outer []string
	// Inner lists protocol layers the handler itself decoded inside its own
	// stream (e.g. "tls", "http" inside a socks tunnel), outermost first.
	Inner []string
}

// Stack returns the protocol layers of a session from the wire up:
// transport, wrapper layers, the handler, then layers nested inside it.
// Consecutive duplicates collapse.
func (m Metadata) Stack(transport, handler string) []string {
	stack := make([]string, 0, 2+len(m.Outer)+len(m.Inner))
	for _, name := range append(append([]string{transport}, m.Outer...), append([]string{handler}, m.Inner...)...) {
		if name == "" || (len(stack) > 0 && stack[len(stack)-1] == name) {
			continue
		}
		stack = append(stack, name)
	}
	return stack
}

// WithOuter returns a copy of m with layers appended to Outer, for a handler
// that handed the session to another one after decoding those layers itself
// (HTTP before MCP, the catch-all's TLS before HTTP).
func (m Metadata) WithOuter(names ...string) Metadata {
	m.Outer = append(slices.Clone(m.Outer), names...)
	return m
}

// AddInner appends a nested layer once, ignoring repeats.
func (m *Metadata) AddInner(names ...string) {
	for _, name := range names {
		if !slices.Contains(m.Inner, name) {
			m.Inner = append(m.Inner, name)
		}
	}
}

type ConnTable struct {
	table map[CKey]Metadata
	mtx   sync.RWMutex
}

func New(ctx context.Context) *ConnTable {
	ct := &ConnTable{
		table: make(map[CKey]Metadata, 1024),
	}
	// every 5 minutes using a ticker, flush the table

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ct.FlushOlderThan(5 * time.Minute)
			}
		}
	}()

	return ct
}

// RegisterConn a connection in the table
func (t *ConnTable) RegisterConn(conn net.Conn, rule *rules.Rule) (Metadata, error) {
	srcIP, srcPort, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to split remote address: %w", err)
	}

	dstHost, dstPort, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to split local address: %w", err)
	}
	port, err := strconv.Atoi(dstPort)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to parse dstPort: %w", err)
	}
	return t.Register(srcIP, srcPort, uint16(port), dstHost, rule)
}

// Register a connection in the table
func (t *ConnTable) Register(srcIP, srcPort string, dstPort uint16, dstHost string, rule *rules.Rule) (Metadata, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ck, err := NewConnKeyByString(srcIP, srcPort)
	if err != nil {
		return Metadata{}, err
	}
	if md, ok := t.table[ck]; ok {
		return md, nil
	}

	md := NewMetadata(dstPort, dstHost, rule)
	t.table[ck] = md
	return md, nil
}

// NewMetadata returns metadata for a flow that starts now. UDP datagrams use
// it directly instead of Register: the table is keyed on source address only,
// so a cached entry would hand a later datagram (or a later TCP connection
// from the same source port) the start time and rule of an earlier one.
func NewMetadata(dstPort uint16, dstHost string, rule *rules.Rule) Metadata {
	return Metadata{
		Added:      time.Now(),
		TargetPort: dstPort,
		TargetIP:   dstHost,
		Rule:       rule,
	}
}

func (t *ConnTable) FlushOlderThan(s time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	threshold := time.Now().Add(-1 * s)

	for ck, md := range t.table {
		if md.Added.Before(threshold) {
			delete(t.table, ck)
		}
	}
}

// TODO: what happens when I return a *Metadata and then FlushOlderThan() deletes it?
func (t *ConnTable) Get(ck CKey) Metadata {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.table[ck]
}

// TLSInfo describes a TLS session terminated by the sensor before the
// protocol handler ran. Hello holds the raw ClientHello records (capped);
// JA3, JA3N, JA4 and JA4R are its fingerprints, empty when it did not parse.
type TLSInfo struct {
	ServerName string
	ALPN       []string
	Version    string
	Cipher     string
	Hello      []byte
	Truncated  bool
	JA3        string
	JA3N       string
	JA4        string
	JA4R       string
}
