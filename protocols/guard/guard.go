// Package guard bounds the bytes the honeypot sends so it cannot be turned
// into an amplifier, reflector or bandwidth sink. Every reply is charged
// against a token bucket for its destination IP (for UDP the claimed request
// source, i.e. the would-be victim; for TCP the connected peer) and against
// one global bucket. A reply that does not fit either bucket is refused: UDP
// callers drop it, a guarded TCP Conn fails the Write with ErrLimited. Each
// network gets its own Guard so their budgets stay independent. It is
// in-memory only: per-destination state is bounded by Config.MaxSources
// (least recently charged dropped first).
package guard

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
)

// UDP defaults: replies go to an unverified (possibly spoofed) address, so
// budgets are tight.
const (
	DefaultSourceRate  = 512
	DefaultSourceBurst = 8 << 10
	DefaultGlobalRate  = 128 << 10
	DefaultGlobalBurst = 1 << 20
	DefaultMaxSources  = 65536
)

// TCP defaults: the peer completed a handshake, so budgets only bound how
// much one source (or all sources) can pull from the honeypot. The source
// burst must exceed the largest single Write a handler or proxy makes.
const (
	DefaultTCPSourceRate  = 64 << 10
	DefaultTCPSourceBurst = 1 << 20
	DefaultTCPGlobalRate  = 8 << 20
	DefaultTCPGlobalBurst = 32 << 20
)

// Config sets the reply budgets. Rates are bytes per second, bursts are the
// most bytes a bucket holds; a reply larger than a burst is never sent.
type Config struct {
	Enabled bool
	// SourceRate and SourceBurst bound reply bytes to one destination IP.
	SourceRate  int
	SourceBurst int
	// GlobalRate and GlobalBurst bound reply bytes to all destinations
	// together, which also covers floods spoofed across many victim IPs.
	// A GlobalRate of 0 disables the global bucket.
	GlobalRate  int
	GlobalBurst int
	// MaxSources caps the destinations tracked.
	MaxSources int
}

// DefaultTCPConfig returns the enabled guard defaults for TCP.
func DefaultTCPConfig() Config {
	return Config{
		Enabled:     true,
		SourceRate:  DefaultTCPSourceRate,
		SourceBurst: DefaultTCPSourceBurst,
		GlobalRate:  DefaultTCPGlobalRate,
		GlobalBurst: DefaultTCPGlobalBurst,
		MaxSources:  DefaultMaxSources,
	}
}

// DefaultConfig returns the enabled guard defaults for UDP.
func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		SourceRate:  DefaultSourceRate,
		SourceBurst: DefaultSourceBurst,
		GlobalRate:  DefaultGlobalRate,
		GlobalBurst: DefaultGlobalBurst,
		MaxSources:  DefaultMaxSources,
	}
}

// Limit names the bucket that refused a reply.
type Limit string

const (
	LimitNone   Limit = ""
	LimitSource Limit = "source"
	LimitGlobal Limit = "global"
)

// Decision is the outcome of Allow.
type Decision struct {
	Allowed bool
	// Limit is the bucket that refused the reply.
	Limit Limit
	// First is true on the first refusal after the bucket last allowed a
	// reply, so callers can log once per limited episode instead of once per
	// dropped packet.
	First bool
}

type bucket struct {
	tokens  float64
	last    time.Time
	limited bool
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	if b.last.IsZero() {
		b.tokens = burst
	} else if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(burst, b.tokens+d*rate)
	}
	b.last = now
}

// refuse marks the bucket limited and reports whether that is new.
func (b *bucket) refuse() bool {
	first := !b.limited
	b.limited = true
	return first
}

type entry struct {
	addr netip.Addr
	bucket
}

// Guard charges replies against per-destination and global budgets. The zero
// value is not usable; use New.
type Guard struct {
	mu      sync.Mutex
	cfg     Config
	now     func() time.Time
	global  bucket
	sources map[netip.Addr]*list.Element
	order   *list.List // front = most recently charged
}

// New returns a guard with cfg; zero or negative fields fall back to defaults.
func New(cfg Config) *Guard {
	def := DefaultConfig()
	if cfg.SourceRate <= 0 {
		cfg.SourceRate = def.SourceRate
	}
	if cfg.SourceBurst <= 0 {
		cfg.SourceBurst = def.SourceBurst
	}
	if cfg.GlobalRate < 0 {
		cfg.GlobalRate = def.GlobalRate
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = def.GlobalBurst
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = def.MaxSources
	}
	return &Guard{
		cfg:     cfg,
		now:     time.Now,
		sources: make(map[netip.Addr]*list.Element),
		order:   list.New(),
	}
}

// Allow charges a reply of size bytes to dst and reports whether it may be
// sent. A refused reply consumes nothing.
func (g *Guard) Allow(dst net.IP, size int) Decision {
	if g == nil || !g.cfg.Enabled {
		return Decision{Allowed: true}
	}
	addr, ok := netip.AddrFromSlice(dst)
	if !ok {
		return Decision{Limit: LimitSource}
	}
	addr = addr.Unmap()
	n := float64(size)

	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	src := g.source(addr)
	src.refill(now, float64(g.cfg.SourceRate), float64(g.cfg.SourceBurst))
	if src.tokens < n {
		return Decision{Limit: LimitSource, First: src.refuse()}
	}
	if g.cfg.GlobalRate > 0 {
		g.global.refill(now, float64(g.cfg.GlobalRate), float64(g.cfg.GlobalBurst))
		if g.global.tokens < n {
			return Decision{Limit: LimitGlobal, First: g.global.refuse()}
		}
		g.global.tokens -= n
		g.global.limited = false
	}
	src.tokens -= n
	src.limited = false
	return Decision{Allowed: true}
}

// source returns the bucket for addr, creating it and evicting the least
// recently charged destination when full. Caller holds g.mu.
func (g *Guard) source(addr netip.Addr) *bucket {
	if el, ok := g.sources[addr]; ok {
		g.order.MoveToFront(el)
		return &el.Value.(*entry).bucket
	}
	for g.order.Len() >= g.cfg.MaxSources {
		oldest := g.order.Back()
		delete(g.sources, oldest.Value.(*entry).addr)
		g.order.Remove(oldest)
	}
	e := &entry{addr: addr}
	g.sources[addr] = g.order.PushFront(e)
	return &e.bucket
}

// Len returns the number of destinations tracked.
func (g *Guard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.order.Len()
}
