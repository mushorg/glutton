package guard

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newConnLimiter(cfg ConnLimitConfig) (*ConnLimiter, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := NewConnLimiter(cfg)
	l.now = c.now
	return l, c
}

func TestConnLimiterCapsPrefix(t *testing.T) {
	// SOCKS flood spread over 149.86.227.0/24
	l, _ := newConnLimiter(ConnLimitConfig{Enabled: true, SourceMax: 3, SourcePrefixV4: 24, SourcePrefixV6: 48})

	var releases []func()
	for _, ip := range []string{"149.86.227.19", "149.86.227.41", "::ffff:149.86.227.96"} {
		r, d := l.Acquire(net.ParseIP(ip))
		require.True(t, d.Allowed, ip)
		releases = append(releases, r)
	}
	require.Equal(t, 3, l.Open(net.ParseIP("149.86.227.1")))

	_, d := l.Acquire(net.ParseIP("149.86.227.140"))
	require.Equal(t, Decision{Limit: LimitSourceConns, First: true}, d, "the /24 shares one cap")
	_, d = l.Acquire(net.ParseIP("149.86.227.24"))
	require.Equal(t, Decision{Limit: LimitSourceConns}, d, "only the first refusal is flagged")

	_, d = l.Acquire(net.ParseIP("149.86.228.1"))
	require.True(t, d.Allowed, "another /24 has its own cap")

	releases[0]()
	releases[0]() // idempotent
	require.Equal(t, 2, l.Open(net.ParseIP("149.86.227.1")), "a double release frees one slot")
	_, d = l.Acquire(net.ParseIP("149.86.227.140"))
	require.True(t, d.Allowed, "a released slot can be taken again")
}

func TestConnLimiterIPv6Prefix(t *testing.T) {
	l, _ := newConnLimiter(ConnLimitConfig{Enabled: true, SourceMax: 1, SourcePrefixV4: 24, SourcePrefixV6: 48})
	_, d := l.Acquire(net.ParseIP("2001:db8:1:2::1"))
	require.True(t, d.Allowed)
	_, d = l.Acquire(net.ParseIP("2001:db8:1:ffff::9"))
	require.False(t, d.Allowed, "the /48 shares one cap")
	_, d = l.Acquire(net.ParseIP("2001:db8:2::1"))
	require.True(t, d.Allowed)
}

func TestConnLimiterForgetsDrainedPrefixes(t *testing.T) {
	l, c := newConnLimiter(ConnLimitConfig{Enabled: true, SourceMax: 1, SourcePrefixV4: 24})
	r, _ := l.Acquire(victim)
	r()
	require.Zero(t, l.Len(), "an unlimited prefix is dropped when its last conn closes")

	r, _ = l.Acquire(victim)
	_, d := l.Acquire(victim)
	require.True(t, d.First)
	r()
	require.Equal(t, 1, l.Len(), "a recently warned prefix is kept so it does not warn again at once")
	r, _ = l.Acquire(victim)
	_, d = l.Acquire(victim)
	require.Equal(t, Decision{Limit: LimitSourceConns}, d, "no second warning within WarnInterval")
	r()

	c.advance(WarnInterval)
	_, d = l.Acquire(other) // any Acquire sweeps
	require.True(t, d.Allowed)
	require.Equal(t, 1, l.Len(), "the drained prefix is swept after WarnInterval")
}

func TestConnLimiterDisabled(t *testing.T) {
	var nilLimiter *ConnLimiter
	r, d := nilLimiter.Acquire(victim)
	require.True(t, d.Allowed)
	r()
	l := NewConnLimiter(ConnLimitConfig{Enabled: false, SourceMax: 1})
	for range 3 {
		_, d := l.Acquire(victim)
		require.True(t, d.Allowed)
	}
	require.Zero(t, l.Len())
}

func TestNewConnLimiterDefaults(t *testing.T) {
	require.Equal(t, DefaultSourceMaxConns, NewConnLimiter(ConnLimitConfig{Enabled: true}).cfg.SourceMax)
}
