package tcp

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

// sessionIdle overrides the session flush delay in tests (atomic: idle
// timers read it while test cleanup restores it). When zero, production uses
// conn_timeout (default 45s) so follow-up requests on new connections can
// still append to the same produced event.
var sessionIdle atomic.Int64

func sessionIdleDuration() time.Duration {
	if d := time.Duration(sessionIdle.Load()); d > 0 {
		return d
	}
	if secs := viper.GetInt("conn_timeout"); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 45 * time.Second
}

// Bounds for one session. Once a session reaches any of them, the next frame
// or connection that would join it (by client-supplied id or by source host)
// starts a new session under the same id, so a persistent client cannot grow
// one event forever.
const (
	maxSessionFrames = 500
	maxSessionBytes  = 8 << 20 // summed spec.size of the frames
	maxSessionAge    = time.Hour
)

// maxSessions caps the sessions one table tracks. When it is full, the
// session idle the longest is produced early with endReason evicted; if every
// session has an open connection, the new connection keeps its frames and
// produces its own event.
const maxSessions = 1024

func sessionKey(srcHost, sessionID string) string {
	return srcHost + "|" + sessionID
}

type sessionSpec[T any] struct {
	protocol string
	payload  func([]T) []byte
	stamp    func(*T, string)
	size     func(T) int // bytes a frame holds, counted against maxSessionBytes
	// groupBySource makes ensure() join the latest live session from the same
	// source host instead of starting a new one, for clients (scanners) that
	// never echo the session id back.
	groupBySource bool
}

type sessionTable[T any] struct {
	mu       sync.Mutex
	limit    int
	sessions map[string]*trackedSession[T]
	bySource map[string]*trackedSession[T]
}

func newSessionTable[T any]() *sessionTable[T] {
	return &sessionTable[T]{
		limit:    maxSessions,
		sessions: map[string]*trackedSession[T]{},
		bySource: map[string]*trackedSession[T]{},
	}
}

// getOrCreate returns the session stored under key, creating it atomically so
// concurrent connections with the same id share one session. A full session
// is replaced under the same key; it still produces once its connections end.
// The session comes back acquired; nil means the table is full of sessions
// with open connections.
func (t *sessionTable[T]) getOrCreate(key string, create func() *trackedSession[T]) *trackedSession[T] {
	t.mu.Lock()
	s, evicted := t.joinLocked(t.sessions[key], create)
	t.mu.Unlock()
	if evicted != nil {
		evicted.finish(true, connection.EndEvicted)
	}
	return s
}

// forSource is getOrCreate for the latest session of src.
func (t *sessionTable[T]) forSource(src string, create func() *trackedSession[T]) *trackedSession[T] {
	t.mu.Lock()
	s, evicted := t.joinLocked(t.bySource[src], create)
	t.mu.Unlock()
	if evicted != nil {
		evicted.finish(true, connection.EndEvicted)
	}
	return s
}

// joinLocked acquires cur when it is still joinable, else registers a new
// session. Acquiring under t.mu means neither the idle timer nor an eviction
// can produce the session before the caller attaches to it. evicted, when
// set, was removed to make room and must be finished after t.mu is released.
func (t *sessionTable[T]) joinLocked(cur *trackedSession[T], create func() *trackedSession[T]) (s, evicted *trackedSession[T]) {
	if cur != nil && cur.tryAcquire() {
		return cur, nil
	}
	s = create()
	if _, replacing := t.sessions[s.key]; !replacing && len(t.sessions) >= t.limit {
		if evicted = t.idlestLocked(); evicted == nil {
			return nil, nil
		}
		t.removeLocked(evicted)
	}
	s.acquire()
	t.putLocked(s)
	return s, evicted
}

// idlestLocked returns the session without open connections that has been
// idle the longest, or nil.
func (t *sessionTable[T]) idlestLocked() *trackedSession[T] {
	var oldest *trackedSession[T]
	var oldestSince time.Time
	for _, s := range t.sessions {
		s.mu.Lock()
		idle, since := s.refs == 0 && !s.produced, s.idleSince
		s.mu.Unlock()
		if idle && (oldest == nil || since.Before(oldestSince)) {
			oldest, oldestSince = s, since
		}
	}
	return oldest
}

func (t *sessionTable[T]) putLocked(s *trackedSession[T]) {
	t.sessions[s.key] = s
	if s.src != "" {
		t.bySource[s.src] = s
	}
}

func (t *sessionTable[T]) remove(expected *trackedSession[T]) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(expected)
}

func (t *sessionTable[T]) removeLocked(expected *trackedSession[T]) {
	key := expected.key
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
	bytes     int
	md        connection.Metadata
	remote    net.Addr
	h         interfaces.Honeypot
	logger    interfaces.Logger
	refs      int
	idleSince time.Time // when refs last dropped to 0
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
	for i := range frames {
		if s.spec.stamp != nil {
			s.spec.stamp(&frames[i], s.id)
		}
		if s.spec.size != nil {
			s.bytes += s.spec.size(frames[i])
		}
	}
	s.events = append(s.events, frames...)
	s.stopIdleLocked()
}

// joinable reports whether another connection may still be added to this
// session.
func (s *trackedSession[T]) joinable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.joinableLocked()
}

func (s *trackedSession[T]) joinableLocked() bool {
	return !s.produced && len(s.events) < maxSessionFrames && s.bytes < maxSessionBytes && time.Since(s.started) < maxSessionAge
}

// tryAcquire takes a reference if the session is still joinable.
func (s *trackedSession[T]) tryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.joinableLocked() {
		return false
	}
	s.refs++
	s.stopIdleLocked()
	return true
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

// armIdleLocked schedules the produce once the last connection ended. A
// session that can no longer be joined is produced right away.
func (s *trackedSession[T]) armIdleLocked() {
	s.stopIdleLocked()
	s.idleSince = time.Now()
	d := sessionIdleDuration()
	if !s.joinableLocked() {
		d = 0
	}
	s.idleTimer = time.AfterFunc(d, func() { s.finish(true, "") })
}

func (s *trackedSession[T]) produce() {
	s.finish(false, "")
}

// finish produces the session once. With idleOnly it does nothing while a
// connection holds the session (a timer or eviction raced an acquire).
// endReason, when set, overrides the last connection's.
func (s *trackedSession[T]) finish(idleOnly bool, endReason string) {
	s.mu.Lock()
	if s.produced || (idleOnly && s.refs > 0) {
		s.mu.Unlock()
		return
	}
	if endReason != "" {
		s.md.EndReason = endReason
	}
	s.produced = true
	s.stopIdleLocked()
	events := append([]T(nil), s.events...)
	md := s.md
	remote := s.remote
	h := s.h
	logger := s.logger
	table := s.table
	spec := s.spec
	s.mu.Unlock()

	table.remove(s)

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
	t.attach(t.table.getOrCreate(sessionKey(t.srcHost, id), t.newSession(id)), id)
}

// attach switches to sess, which the table already acquired for us. A nil
// sess (table full) leaves the frames on this connection under id.
func (t *sessionTracker[T]) attach(sess *trackedSession[T], id string) {
	if sess != nil && sess == t.session {
		sess.release()
		return
	}
	if t.session != nil {
		t.session.release()
		t.session = nil
	}
	t.sessionID = id
	if sess == nil {
		return
	}
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
	// keep the id handed out earlier when the table was full
	id := t.sessionID
	if id == "" {
		id = uuid.NewString()
	}
	if t.spec.groupBySource && t.srcHost != "" {
		t.attach(t.table.forSource(t.srcHost, t.newSession(id)), id)
		return
	}
	t.bind(id)
}

func (t *sessionTracker[T]) record(frame T) {
	if t.session != nil && !t.session.joinable() {
		// full: continue in a new session under the same id
		id := t.session.id
		t.attach(t.table.getOrCreate(sessionKey(t.srcHost, id), t.newSession(id)), id)
	}
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
