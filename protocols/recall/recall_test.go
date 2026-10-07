package recall

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time             { return c.t }
func (c *clock) advance(d time.Duration)    { c.t = c.t.Add(d) }
func newClock() *clock                      { return &clock{t: time.Unix(1700000000, 0)} }
func testStore(c *clock, cfg Config) *Store { return NewWithClock(cfg, c.now) }

var ip = net.ParseIP("192.0.2.10")

func TestBeginSameVisitWithinGap(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute})
	v := s.Begin("sip", ip, 3)
	require.Equal(t, Visit{Number: 1, Started: true}, v)
	c.advance(59 * time.Second)
	require.Equal(t, Visit{Number: 1}, s.Begin("sip", ip, 3))
	// activity refreshes last seen, so the gap counts from the latest datagram
	c.advance(59 * time.Second)
	require.Equal(t, 1, s.Begin("sip", ip, 3).Number)
}

func TestBeginRoundRobinAndPrevious(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute})
	var variants []int
	for i := range 5 {
		v := s.Begin("sip", ip, 3)
		require.Equal(t, i+1, v.Number)
		require.True(t, v.Started)
		if i > 0 {
			require.Equal(t, fmt.Sprint(i-1), v.Previous.Variant)
			require.Equal(t, i, v.Previous.Events)
		} else {
			require.Equal(t, Summary{}, v.Previous)
		}
		s.Note("sip", ip, func(sum *Summary) {
			sum.Variant = fmt.Sprint(i)
			sum.Events = i + 1
		})
		variants = append(variants, v.Variant)
		c.advance(time.Minute)
	}
	require.Equal(t, []int{0, 1, 2, 0, 1}, variants)
}

func TestBeginKeysByProtocolAndIP(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute})
	s.Begin("sip", ip, 2)
	c.advance(time.Minute)
	require.Equal(t, 2, s.Begin("sip", ip, 2).Number)
	require.Equal(t, 1, s.Begin("ftp", ip, 2).Number)
	require.Equal(t, 1, s.Begin("sip", net.ParseIP("192.0.2.11"), 2).Number)
}

func TestBeginTTLForgets(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute, TTL: time.Hour})
	s.Begin("sip", ip, 2)
	s.Note("sip", ip, func(sum *Summary) { sum.Events = 1 })
	c.advance(time.Hour)
	v := s.Begin("sip", ip, 2)
	require.Equal(t, Visit{Number: 1, Started: true}, v)
}

func TestBeginEvictsLeastRecentlySeen(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute, Max: 2})
	a, b, d := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")
	s.Begin("sip", a, 2)
	s.Begin("sip", b, 2)
	c.advance(time.Minute)
	s.Begin("sip", a, 2) // a is now most recent, visit 2
	s.Begin("sip", d, 2) // evicts b
	require.Equal(t, 2, s.Len())
	c.advance(time.Minute)
	require.Equal(t, 3, s.Begin("sip", a, 2).Number)
	require.Equal(t, 1, s.Begin("sip", b, 2).Number)
}

func TestTrimDropsExpired(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute, TTL: time.Hour})
	s.Begin("sip", net.ParseIP("192.0.2.1"), 2)
	c.advance(time.Hour)
	s.Begin("sip", net.ParseIP("192.0.2.2"), 2)
	require.Equal(t, 1, s.Len())
}

func TestNoteCapsAndDedups(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute})
	s.Begin("sip", ip, 2)
	s.Note("sip", ip, func(sum *Summary) {
		for i := range 40 {
			sum.AddCommand(fmt.Sprint("C", i%20))
			sum.AddPath(fmt.Sprint("P", i))
			sum.AddUsername(fmt.Sprint("U", i))
		}
		sum.AddCommand("C0")
		sum.AddUsername("")
	})
	c.advance(time.Minute)
	prev := s.Begin("sip", ip, 2).Previous
	require.Len(t, prev.Commands, maxCommands)
	require.Equal(t, "C0", prev.Commands[0])
	require.Len(t, prev.Paths, maxPaths)
	require.Len(t, prev.Usernames, maxUsernames)
}

func TestNoteWithoutBegin(t *testing.T) {
	s := testStore(newClock(), DefaultConfig())
	s.Note("sip", ip, func(*Summary) { t.Fatal("called without a visit") })
	require.Equal(t, 0, s.Len())
}

func TestDisabled(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: false, Gap: time.Minute})
	s.Begin("sip", ip, 3)
	c.advance(time.Minute)
	require.Equal(t, Visit{Number: 1, Started: true}, s.Begin("sip", ip, 3))
	s.Note("sip", ip, func(*Summary) { t.Fatal("called while disabled") })
	require.Equal(t, 0, s.Len())
}

func TestCountPerVisit(t *testing.T) {
	c := newClock()
	s := testStore(c, Config{Enabled: true, Gap: time.Minute})
	other := net.ParseIP("192.0.2.11")
	require.Equal(t, 0, s.Count("sip", ip, "invite"), "no visit yet")

	s.Begin("sip", ip, 2)
	s.Begin("sip", other, 2)
	require.Equal(t, 1, s.Count("sip", ip, "invite"))
	require.Equal(t, 2, s.Count("sip", ip, "invite"))
	require.Equal(t, 1, s.Count("sip", ip, "other"))
	require.Equal(t, 1, s.Count("sip", other, "invite"))

	// activity inside the gap keeps the count
	c.advance(59 * time.Second)
	s.Begin("sip", ip, 2)
	require.Equal(t, 3, s.Count("sip", ip, "invite"))

	// a new visit starts from zero
	c.advance(time.Minute)
	s.Begin("sip", ip, 2)
	require.Equal(t, 1, s.Count("sip", ip, "invite"))
}

func TestCountDisabled(t *testing.T) {
	s := testStore(newClock(), Config{Enabled: false})
	s.Begin("sip", ip, 2)
	require.Equal(t, 0, s.Count("sip", ip, "invite"))
}
