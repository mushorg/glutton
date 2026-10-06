package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
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
	EndClientClose  = "client_close"
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

	md := Metadata{
		Added:      time.Now(),
		TargetPort: dstPort,
		TargetIP:   dstHost,
		Rule:       rule,
	}
	t.table[ck] = md
	return md, nil
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
