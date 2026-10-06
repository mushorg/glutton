package tcp

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

// sessionIdle overrides the session flush delay in tests. When zero,
// production uses conn_timeout (default 45s) so follow-up requests on new
// connections can still append to the same produced event.
var sessionIdle time.Duration

func sessionIdleDuration() time.Duration {
	if sessionIdle > 0 {
		return sessionIdle
	}
	if secs := viper.GetInt("conn_timeout"); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 45 * time.Second
}

// Bounds for sessions joined by source host alone (no client-supplied id).
// Once a session reaches either limit, the next cookieless connection from
// that host starts a new session, so a persistent scanner cannot grow one
// event forever.
const (
	maxSourceSessionFrames = 500
	maxSourceSessionAge    = time.Hour
)

func sessionKey(srcHost, sessionID string) string {
	return srcHost + "|" + sessionID
}

type sessionSpec[T any] struct {
	protocol string
	payload  func([]T) []byte
	stamp    func(*T, string)
	// groupBySource makes ensure() join the latest live session from the same
	// source host instead of starting a new one, for clients (scanners) that
	// never echo the session id back.
	groupBySource bool
}

type sessionTable[T any] struct {
	mu       sync.Mutex
	sessions map[string]*trackedSession[T]
	bySource map[string]*trackedSession[T]
}

func newSessionTable[T any]() *sessionTable[T] {
	return &sessionTable[T]{
		sessions: map[string]*trackedSession[T]{},
		bySource: map[string]*trackedSession[T]{},
	}
}

// getOrCreate returns the session stored under key, creating it atomically so
// concurrent connections with the same id share one session.
func (t *sessionTable[T]) getOrCreate(key string, create func() *trackedSession[T]) *trackedSession[T] {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.sessions[key]; ok {
		return s
	}
	s := create()
	t.putLocked(s)
	return s
}

// forSource returns the latest joinable session for src, or creates one.
func (t *sessionTable[T]) forSource(src string, create func() *trackedSession[T]) *trackedSession[T] {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.bySource[src]; ok && s.joinable() {
		return s
	}
	s := create()
	t.putLocked(s)
	return s
}

func (t *sessionTable[T]) putLocked(s *trackedSession[T]) {
	t.sessions[s.key] = s
	if s.src != "" {
		t.bySource[s.src] = s
	}
}

func (t *sessionTable[T]) remove(key string, expected *trackedSession[T]) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.sessions[key]; ok && current == expected {
		delete(t.sessions, key)
	}
	if current, ok := t.bySource[expected.src]; ok && current == expected {
		delete(t.bySource, expected.src)
	}
}

func (t *sessionTable[T]) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = map[string]*trackedSession[T]{}
	t.bySource = map[string]*trackedSession[T]{}
}

// remoteAddrConn exposes a stored remote address for ProduceTCP after the real conn closed.
type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

// trackedSession aggregates frames across TCP connections that share a session id.
type trackedSession[T any] struct {
	mu        sync.Mutex
	id        string
	key       string
	src       string
	started   time.Time
	events    []T
	md        connection.Metadata
	remote    net.Addr
	h         interfaces.Honeypot
	logger    interfaces.Logger
	refs      int
	idleTimer *time.Timer
	produced  bool
	table     *sessionTable[T]
	spec      sessionSpec[T]
}

func (s *trackedSession[T]) append(frames ...T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced {
		return
	}
	if s.spec.stamp != nil {
		for i := range frames {
			s.spec.stamp(&frames[i], s.id)
		}
	}
	s.events = append(s.events, frames...)
	s.stopIdleLocked()
}

// joinable reports whether a cookieless connection from the same source may
// still be added to this session.
func (s *trackedSession[T]) joinable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.produced && len(s.events) < maxSourceSessionFrames && time.Since(s.started) < maxSourceSessionAge
}

func (s *trackedSession[T]) acquire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs++
	s.stopIdleLocked()
}

func (s *trackedSession[T]) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs > 0 {
		s.refs--
	}
	if s.refs == 0 && !s.produced {
		s.armIdleLocked()
	}
}

func (s *trackedSession[T]) stopIdleLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

func (s *trackedSession[T]) armIdleLocked() {
	s.stopIdleLocked()
	s.idleTimer = time.AfterFunc(sessionIdleDuration(), s.produce)
}

func (s *trackedSession[T]) produce() {
	s.mu.Lock()
	if s.produced {
		s.mu.Unlock()
		return
	}
	s.produced = true
	s.stopIdleLocked()
	events := append([]T(nil), s.events...)
	md := s.md
	remote := s.remote
	h := s.h
	logger := s.logger
	key := s.key
	table := s.table
	spec := s.spec
	s.mu.Unlock()

	table.remove(key, s)

	if len(events) == 0 || h == nil {
		return
	}
	conn := &remoteAddrConn{remote: remote}
	payload := spec.payload(events)
	if err := h.ProduceTCP(spec.protocol, conn, md, payload, events); err != nil {
		logger.Error("Failed to produce message", slog.String("protocol", spec.protocol), producer.ErrAttr(err))
	}
}

func (s *trackedSession[T]) endNow() {
	s.mu.Lock()
	s.refs = 0
	s.mu.Unlock()
	s.produce()
}

type sessionTracker[T any] struct {
	local     []T
	session   *trackedSession[T]
	sessionID string
	srcHost   string
	table     *sessionTable[T]
	spec      sessionSpec[T]
	md        connection.Metadata
	remote    net.Addr
	h         interfaces.Honeypot
	logger    interfaces.Logger
}

func (t *sessionTracker[T]) newSession(id string) func() *trackedSession[T] {
	return func() *trackedSession[T] {
		src := ""
		if t.spec.groupBySource {
			src = t.srcHost
		}
		return &trackedSession[T]{
			id:      id,
			key:     sessionKey(t.srcHost, id),
			src:     src,
			started: time.Now(),
			events:  []T{},
			md:      t.md,
			remote:  t.remote,
			h:       t.h,
			logger:  t.logger,
			table:   t.table,
			spec:    t.spec,
		}
	}
}

func (t *sessionTracker[T]) bind(id string) {
	if id == "" {
		return
	}
	if t.session != nil && t.session.id == id {
		t.sessionID = id
		return
	}
	t.attach(t.table.getOrCreate(sessionKey(t.srcHost, id), t.newSession(id)))
}

func (t *sessionTracker[T]) attach(sess *trackedSession[T]) {
	if t.session == sess {
		t.sessionID = sess.id
		return
	}
	if t.session != nil {
		t.session.release()
		t.session = nil
	}
	sess.acquire()
	if len(t.local) > 0 {
		sess.append(t.local...)
		t.local = nil
	}
	t.session = sess
	t.sessionID = sess.id
}

// ensure binds the connection to a session when the client sent no id. With
// groupBySource it joins the source host's latest live session, so separate
// connections (and destination ports) from one scanner become one event.
func (t *sessionTracker[T]) ensure() {
	if t.session != nil {
		return
	}
	if t.spec.groupBySource && t.srcHost != "" {
		t.attach(t.table.forSource(t.srcHost, t.newSession(uuid.NewString())))
		return
	}
	t.bind(uuid.NewString())
}

func (t *sessionTracker[T]) record(frame T) {
	if t.spec.stamp != nil && t.sessionID != "" {
		t.spec.stamp(&frame, t.sessionID)
	}
	if t.session != nil {
		t.session.append(frame)
		return
	}
	t.local = append(t.local, frame)
}

func (t *sessionTracker[T]) closeAndProduce(conn net.Conn) {
	if t.session != nil {
		t.session.mu.Lock()
		t.session.md.EndReason = t.md.EndReason
		t.session.mu.Unlock()
		t.session.release()
		t.session = nil
		return
	}
	if len(t.local) == 0 || t.h == nil {
		return
	}
	if err := t.h.ProduceTCP(t.spec.protocol, conn, t.md, t.spec.payload(t.local), t.local); err != nil {
		t.logger.Error("Failed to produce message", slog.String("protocol", t.spec.protocol), producer.ErrAttr(err))
	}
}
