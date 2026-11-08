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

// New-connection rate defaults per source prefix. The open cap alone does not
// bound churn: a flood that reconnects as soon as it is reset refills freed
// slots hundreds of times per second, and each slot may cost a TLS handshake.
const (
	DefaultSourceConnRate  = 20
	DefaultSourceConnBurst = 100
)

// ConnLimitConfig caps concurrent connections per source prefix.
type ConnLimitConfig struct {
	Enabled bool
	// SourceMax is the most connections one source prefix may hold open.
	SourceMax int
	// SourceRate is how many new connections per second one source prefix
	// may open, and SourceBurst how many at once. A SourceRate of 0
	// disables the rate check.
	SourceRate  int
	SourceBurst int
	// MaxSources caps the prefixes whose rate is tracked; the least
	// recently seen is dropped first.
	MaxSources int
	// SourcePrefixV4 and SourcePrefixV6 group peers into one count per
	// prefix (e.g. 24 and 48). 0 or the full length counts per address.
	SourcePrefixV4 int
	SourcePrefixV6 int
}

// DefaultConnLimitConfig returns the enabled defaults: 256 open connections
// and 20 new connections per second (burst 100) per /24 (IPv4) or /48 (IPv6).
func DefaultConnLimitConfig() ConnLimitConfig {
	return ConnLimitConfig{
		Enabled:        true,
		SourceMax:      DefaultSourceMaxConns,
		SourceRate:     DefaultSourceConnRate,
		SourceBurst:    DefaultSourceConnBurst,
		MaxSources:     DefaultMaxSources,
		SourcePrefixV4: 24,
		SourcePrefixV6: 48,
	}
}

type connCount struct {
	open   int
	warned time.Time // last refusal flagged First
}

// ConnLimiter counts open connections per source prefix and refuses new ones
// over the cap or over the new-connection rate. A slot is held from Acquire
// until its release func runs. Only prefixes with open connections (or a
// refusal within WarnInterval) are counted, so that memory is bounded by the
// open connections; rate state is bounded by MaxSources. The zero value is
// not usable; use NewConnLimiter.
type ConnLimiter struct {
	mu        sync.Mutex
	cfg       ConnLimitConfig
	now       func() time.Time
	sources   map[netip.Addr]*connCount
	lastSweep time.Time
	// rate charges one request per accepted connection; nil when disabled.
	rate *Guard
}

// NewConnLimiter returns a limiter with cfg; a SourceMax <= 0 falls back to
// DefaultSourceMaxConns, a SourceBurst <= 0 to DefaultSourceConnBurst (when
// the rate is on) and a MaxSources <= 0 to DefaultMaxSources.
func NewConnLimiter(cfg ConnLimitConfig) *ConnLimiter {
	if cfg.SourceMax <= 0 {
		cfg.SourceMax = DefaultSourceMaxConns
	}
	if cfg.SourceRate < 0 {
		cfg.SourceRate = 0
	}
	if cfg.SourceRate > 0 && cfg.SourceBurst <= 0 {
		cfg.SourceBurst = DefaultSourceConnBurst
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultMaxSources
	}
	l := &ConnLimiter{cfg: cfg, now: time.Now, sources: make(map[netip.Addr]*connCount)}
	if cfg.Enabled && cfg.SourceRate > 0 {
		// only the per-source request bucket: no bytes are charged
		// (size 0) and both global buckets are off
		l.rate = New(Config{
			Enabled:            true,
			SourceRequestRate:  cfg.SourceRate,
			SourceRequestBurst: cfg.SourceBurst,
			GlobalRate:         0,
			GlobalRequestRate:  0,
			MaxSources:         cfg.MaxSources,
			SourcePrefixV4:     cfg.SourcePrefixV4,
			SourcePrefixV6:     cfg.SourcePrefixV6,
		})
	}
	return l
}

func noRelease() {}

// Acquire takes a connection slot for ip. When allowed, the caller must call
// release once the connection is done; release is safe to call more than
// once. A refused Decision has Limit LimitSourceConns (open cap) or
// LimitSourceConnRate (new-connection rate) and a no-op release; a refusal
// takes no slot and no rate token.
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
	if l.rate != nil {
		if d := l.rate.Allow(ip, 0); !d.Allowed {
			if c.open == 0 && c.warned.IsZero() {
				delete(l.sources, key)
			}
			return noRelease, Decision{Limit: LimitSourceConnRate, First: d.First}
		}
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
