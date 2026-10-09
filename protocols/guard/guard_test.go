package guard

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newGuard(cfg Config) (*Guard, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	g := New(cfg)
	g.now = c.now
	return g, c
}

var (
	victim = net.ParseIP("192.0.2.1")
	other  = net.ParseIP("192.0.2.2")
)

func TestAllowSourceBurstAndRefill(t *testing.T) {
	g, c := newGuard(Config{Enabled: true, SourceRate: 100, SourceBurst: 1000})

	for range 10 {
		require.True(t, g.Allow(victim, 100).Allowed)
	}
	d := g.Allow(victim, 100)
	require.Equal(t, Decision{Limit: LimitSource, First: true}, d, "burst spent")
	require.Equal(t, Decision{Limit: LimitSource}, g.Allow(victim, 100), "only the first refusal is flagged")

	require.True(t, g.Allow(other, 100).Allowed, "other destinations keep their own budget")

	c.advance(time.Second)
	require.True(t, g.Allow(victim, 100).Allowed, "refilled at SourceRate")
	require.Equal(t, Decision{Limit: LimitSource, First: true}, g.Allow(victim, 100), "new limited episode")

	c.advance(time.Hour)
	for range 10 {
		require.True(t, g.Allow(victim, 100).Allowed, "refill is capped at SourceBurst")
	}
	require.False(t, g.Allow(victim, 100).Allowed)
}

func TestAllowRefusesReplyLargerThanBurst(t *testing.T) {
	g, _ := newGuard(Config{Enabled: true, SourceRate: 100, SourceBurst: 1000})
	require.False(t, g.Allow(victim, 1001).Allowed)
	require.True(t, g.Allow(victim, 1000).Allowed, "refused reply consumed nothing")
}

func TestAllowGlobalBudget(t *testing.T) {
	g, c := newGuard(Config{Enabled: true, SourceRate: 1000, SourceBurst: 1000, GlobalRate: 100, GlobalBurst: 1500})

	require.True(t, g.Allow(victim, 1000).Allowed)
	require.Equal(t, Decision{Limit: LimitGlobal, First: true}, g.Allow(other, 1000))
	require.True(t, g.Allow(other, 500).Allowed, "global refusal did not charge the source")

	c.advance(time.Second)
	require.True(t, g.Allow(net.ParseIP("192.0.2.3"), 100).Allowed)
}

func TestAllowDisabled(t *testing.T) {
	g, _ := newGuard(Config{Enabled: false, SourceRate: 1, SourceBurst: 1})
	require.True(t, g.Allow(victim, 1<<16).Allowed)
	require.Zero(t, g.Len())

	var nilGuard *Guard
	require.True(t, nilGuard.Allow(victim, 1<<16).Allowed)
}

func TestAllowNormalizesMappedIPv4(t *testing.T) {
	g, _ := newGuard(Config{Enabled: true, SourceRate: 1, SourceBurst: 100})
	require.True(t, g.Allow(victim.To4(), 100).Allowed)
	require.False(t, g.Allow(victim.To16(), 1).Allowed, "4-byte and 16-byte forms share one bucket")
	require.Equal(t, 1, g.Len())
}

func TestAllowEvictsLeastRecentlyCharged(t *testing.T) {
	g, _ := newGuard(Config{Enabled: true, SourceRate: 1, SourceBurst: 100, MaxSources: 2})
	require.True(t, g.Allow(victim, 100).Allowed)
	require.True(t, g.Allow(other, 100).Allowed)
	require.False(t, g.Allow(victim, 1).Allowed, "touch victim so other is oldest")
	require.True(t, g.Allow(net.ParseIP("192.0.2.3"), 1).Allowed)
	require.Equal(t, 2, g.Len())
	require.False(t, g.Allow(victim, 1).Allowed, "victim kept")
	require.True(t, g.Allow(other, 100).Allowed, "other was evicted and starts full")
}

func TestNewAppliesDefaults(t *testing.T) {
	g := New(Config{Enabled: true})
	want := DefaultConfig()
	want.GlobalRate = 0
	require.Equal(t, want, g.cfg, "GlobalRate 0 keeps the global bucket disabled")
}

func TestDefaultTCPConfigSurvivesNew(t *testing.T) {
	require.Equal(t, DefaultTCPConfig(), New(DefaultTCPConfig()).cfg)
}

type addrConn struct {
	net.Conn
	remote net.Addr
	wrote  []byte
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }
func (c *addrConn) Write(p []byte) (int, error) {
	c.wrote = append(c.wrote, p...)
	return len(p), nil
}

func TestWrapChargesRemoteIP(t *testing.T) {
	g, _ := newGuard(Config{Enabled: true, SourceRate: 1, SourceBurst: 10})
	var refused []Decision
	onLimit := func(_ net.Conn, d Decision, size int) {
		require.Equal(t, 5, size)
		refused = append(refused, d)
	}
	a := &addrConn{remote: &net.TCPAddr{IP: victim, Port: 1}}
	b := &addrConn{remote: &net.TCPAddr{IP: victim, Port: 2}}
	ca, cb := g.Wrap(a, onLimit), g.Wrap(b, onLimit)

	_, err := ca.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = cb.Write([]byte("world"))
	require.NoError(t, err, "connections from one IP share a budget")
	n, err := ca.Write([]byte("again"))
	require.ErrorIs(t, err, ErrLimited)
	require.Zero(t, n)
	require.Equal(t, "hello", string(a.wrote), "refused write sent nothing")
	require.Equal(t, []Decision{{Limit: LimitSource, First: true}}, refused)
}

func TestWrapPassThrough(t *testing.T) {
	a := &addrConn{remote: &net.TCPAddr{IP: victim, Port: 1}}
	var nilGuard *Guard
	require.Same(t, net.Conn(a), nilGuard.Wrap(a, nil))
	require.Same(t, net.Conn(a), New(Config{Enabled: false}).Wrap(a, nil))
	unix := &addrConn{remote: &net.UnixAddr{Name: "x", Net: "unix"}}
	require.Same(t, net.Conn(unix), New(DefaultTCPConfig()).Wrap(unix, nil), "no IP to charge")
}
