// Package recall remembers what each source did on its last visit to a
// protocol, so handlers can answer a returning source differently and see
// which follow-up behavior each answer triggers. It is in-memory only:
// bounded by Config.Max (least recently seen sources are dropped) and
// Config.TTL.
package recall

import (
	"container/list"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	DefaultGap = 30 * time.Minute
	DefaultTTL = 7 * 24 * time.Hour
	DefaultMax = 65536

	maxCommands  = 16
	maxPaths     = 16
	maxUsernames = 8
)

// Config bounds the store.
type Config struct {
	Enabled bool
	// Gap is the silence after which a returning source starts a new visit.
	Gap time.Duration
	// TTL is how long a source is remembered after it was last seen.
	TTL time.Duration
	// Max caps the sources kept; the least recently seen is dropped first.
	Max int
}

// DefaultConfig returns the enabled store defaults.
func DefaultConfig() Config {
	return Config{Enabled: true, Gap: DefaultGap, TTL: DefaultTTL, Max: DefaultMax}
}

// Summary is what one visit did. Field names mirror the decoded-frame
// contract (command, path, username, user_agent).
type Summary struct {
	Variant   string
	Commands  []string
	Paths     []string
	Usernames []string
	UserAgent string
	Events    int
}

// AddCommand records a command once, up to the cap.
func (s *Summary) AddCommand(v string) { s.Commands = addCapped(s.Commands, v, maxCommands) }

// AddPath records a path once, up to the cap.
func (s *Summary) AddPath(v string) { s.Paths = addCapped(s.Paths, v, maxPaths) }

// AddUsername records a username once, up to the cap.
func (s *Summary) AddUsername(v string) { s.Usernames = addCapped(s.Usernames, v, maxUsernames) }

func addCapped(list []string, v string, limit int) []string {
	if v == "" || len(list) >= limit || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// Visit is the state of a source's current visit.
type Visit struct {
	// Number is 1 for a source seen for the first time (or forgotten).
	Number int
	// Variant indexes the caller's list of response variants. Visit 1 always
	// gets 0, later visits cycle through the list.
	Variant int
	// Previous is the summary of the last finished visit; zero on visit 1.
	Previous Summary
	// Started is true when this Begin opened the visit.
	Started bool
}

type entry struct {
	key      string
	lastSeen time.Time
	visit    Visit
	current  Summary
	counts   map[string]int // per-visit counters, see Count
}

// Store maps (protocol, source IP) to visits. It is safe for concurrent use.
type Store struct {
	mu  sync.Mutex
	cfg Config
	// now is the clock; tests replace it.
	now func() time.Time
	lru *list.List // front is most recently seen
	idx map[string]*list.Element
}

// New returns a store using cfg; zero durations and Max take the defaults.
func New(cfg Config) *Store {
	s := &Store{now: time.Now, lru: list.New(), idx: map[string]*list.Element{}}
	s.Configure(cfg)
	return s
}

// NewWithClock returns a store driven by now, for tests.
func NewWithClock(cfg Config, now func() time.Time) *Store {
	s := New(cfg)
	s.now = now
	return s
}

// Shared is the process-wide store handlers use. Glutton.Init configures it.
var Shared = New(DefaultConfig())

// Configure replaces the store's bounds. Existing entries are kept and
// trimmed to the new Max on the next Begin.
func (s *Store) Configure(cfg Config) {
	if cfg.Gap <= 0 {
		cfg.Gap = DefaultGap
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Max <= 0 {
		cfg.Max = DefaultMax
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

func key(proto string, ip net.IP) string {
	return proto + "|" + ip.String()
}

// Begin marks activity from ip on proto and returns its visit. A source seen
// within Gap stays in the same visit (same variant); otherwise a new visit
// starts, the current summary becomes Previous, and the variant advances
// round-robin over variants.
func (s *Store) Begin(proto string, ip net.IP, variants int) Visit {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cfg.Enabled || ip == nil {
		return Visit{Number: 1, Started: true}
	}
	now := s.now()
	k := key(proto, ip)
	if el, ok := s.idx[k]; ok {
		e := el.Value.(*entry)
		age := now.Sub(e.lastSeen)
		if age >= s.cfg.TTL {
			s.lru.Remove(el)
			delete(s.idx, k)
		} else {
			started := age >= s.cfg.Gap
			if started {
				e.visit.Number++
				e.visit.Previous = e.current
				e.current = Summary{}
				e.counts = nil
				if variants > 0 {
					e.visit.Variant = (e.visit.Number - 1) % variants
				}
			}
			e.lastSeen = now
			s.lru.MoveToFront(el)
			v := e.visit
			v.Started = started
			return v
		}
	}
	e := &entry{key: k, lastSeen: now, visit: Visit{Number: 1}}
	s.idx[k] = s.lru.PushFront(e)
	s.trim(now)
	v := e.visit
	v.Started = true
	return v
}

// trim drops expired sources and the least recently seen beyond Max.
func (s *Store) trim(now time.Time) {
	for s.lru.Len() > 0 {
		el := s.lru.Back()
		e := el.Value.(*entry)
		if s.lru.Len() <= s.cfg.Max && now.Sub(e.lastSeen) < s.cfg.TTL {
			return
		}
		s.lru.Remove(el)
		delete(s.idx, e.key)
	}
}

// Note merges what happened into the current visit of ip on proto. It does
// nothing for a source without a visit (call Begin first).
func (s *Store) Note(proto string, ip net.IP, f func(*Summary)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cfg.Enabled || ip == nil {
		return
	}
	if el, ok := s.idx[key(proto, ip)]; ok {
		f(&el.Value.(*entry).current)
	}
}

// Count increments the counter name in the current visit of ip on proto and
// returns the new value. Counters start at zero with every visit. It returns
// 0 when the store is disabled or the source has no visit (call Begin first).
func (s *Store) Count(proto string, ip net.IP, name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cfg.Enabled || ip == nil {
		return 0
	}
	el, ok := s.idx[key(proto, ip)]
	if !ok {
		return 0
	}
	e := el.Value.(*entry)
	if e.counts == nil {
		e.counts = map[string]int{}
	}
	e.counts[name]++
	return e.counts[name]
}

// Len returns the number of remembered sources.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len()
}
