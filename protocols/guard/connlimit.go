package guard

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultSourceMaxConns is how many TCP connections one source prefix may
// hold open at once. Normal scanners stay far below it; a SOCKS proxy-abuse
// flood from one /24 held ~900.
const DefaultSourceMaxConns = 256

// ConnLimitConfig caps concurrent connections per source prefix.
type ConnLimitConfig struct {
	Enabled bool
	// SourceMax is the most connections one source prefix may hold open.
	SourceMax int
	// SourcePrefixV4 and SourcePrefixV6 group peers into one count per
	// prefix (e.g. 24 and 48). 0 or the full length counts per address.
	SourcePrefixV4 int
	SourcePrefixV6 int
}

// DefaultConnLimitConfig returns the enabled defaults: 256 open connections
// per /24 (IPv4) or /48 (IPv6).
func DefaultConnLimitConfig() ConnLimitConfig {
	return ConnLimitConfig{
		Enabled:        true,
		SourceMax:      DefaultSourceMaxConns,
		SourcePrefixV4: 24,
		SourcePrefixV6: 48,
	}
}

type connCount struct {
	open   int
	warned time.Time // last refusal flagged First
}

// ConnLimiter counts open connections per source prefix and refuses new ones
// over the cap. Unlike Guard it is not a rate: a slot is held from Acquire
// until its release func runs. Only prefixes with open connections (or a
// refusal within WarnInterval) are tracked, so memory is bounded by the open
// connections. The zero value is not usable; use NewConnLimiter.
type ConnLimiter struct {
	mu        sync.Mutex
	cfg       ConnLimitConfig
	now       func() time.Time
	sources   map[netip.Addr]*connCount
	lastSweep time.Time
}

// NewConnLimiter returns a limiter with cfg; a SourceMax <= 0 falls back to
// DefaultSourceMaxConns.
func NewConnLimiter(cfg ConnLimitConfig) *ConnLimiter {
	if cfg.SourceMax <= 0 {
		cfg.SourceMax = DefaultSourceMaxConns
	}
	return &ConnLimiter{cfg: cfg, now: time.Now, sources: make(map[netip.Addr]*connCount)}
}

func noRelease() {}

// Acquire takes a connection slot for ip. When allowed, the caller must call
// release once the connection is done; release is safe to call more than
// once. A refused Decision has Limit LimitSourceConns and a no-op release.
// A nil or disabled limiter, or an ip that is not an address, always allows.
func (l *ConnLimiter) Acquire(ip net.IP) (release func(), d Decision) {
	if l == nil || !l.cfg.Enabled {
		return noRelease, Decision{Allowed: true}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return noRelease, Decision{Allowed: true}
	}
	key := prefixKey(addr.Unmap(), l.cfg.SourcePrefixV4, l.cfg.SourcePrefixV6)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	c := l.sources[key]
	if c == nil {
		c = &connCount{}
		l.sources[key] = c
	}
	if c.open >= l.cfg.SourceMax {
		first := c.warned.IsZero() || now.Sub(c.warned) >= WarnInterval
		if first {
			c.warned = now
		}
		return noRelease, Decision{Limit: LimitSourceConns, First: first}
	}
	c.open++

	var once sync.Once
	return func() { once.Do(func() { l.release(key) }) }, Decision{Allowed: true}
}

func (l *ConnLimiter) release(key netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.sources[key]
	if c == nil {
		return
	}
	c.open--
	if c.open <= 0 && (c.warned.IsZero() || l.now().Sub(c.warned) >= WarnInterval) {
		delete(l.sources, key)
	}
}

// sweep drops prefixes with no open connections whose warning has expired.
// They stay only so a flood that drains and returns does not warn again
// within WarnInterval. Caller holds l.mu.
func (l *ConnLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < WarnInterval {
		return
	}
	l.lastSweep = now
	for k, c := range l.sources {
		if c.open <= 0 && now.Sub(c.warned) >= WarnInterval {
			delete(l.sources, k)
		}
	}
}

// Open returns how many connections the prefix holding ip has open.
func (l *ConnLimiter) Open(ip net.IP) int {
	if l == nil {
		return 0
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return 0
	}
	key := prefixKey(addr.Unmap(), l.cfg.SourcePrefixV4, l.cfg.SourcePrefixV6)
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.sources[key]; c != nil {
		return c.open
	}
	return 0
}

// Len returns the number of prefixes tracked.
func (l *ConnLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}
