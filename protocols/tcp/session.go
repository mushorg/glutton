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

func sessionKey(srcHost, sessionID string) string {
	return srcHost + "|" + sessionID
}

type sessionSpec[T any] struct {
	protocol string
	payload  func([]T) []byte
	stamp    func(*T, string)
}

type sessionTable[T any] struct {
	mu       sync.Mutex
	sessions map[string]*trackedSession[T]
}

func newSessionTable[T any]() *sessionTable[T] {
	return &sessionTable[T]{sessions: map[string]*trackedSession[T]{}}
}

func (t *sessionTable[T]) get(key string) *trackedSession[T] {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[key]
}

func (t *sessionTable[T]) put(s *trackedSession[T]) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[s.key] = s
}

func (t *sessionTable[T]) remove(key string, expected *trackedSession[T]) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.sessions[key]; ok && current == expected {
		delete(t.sessions, key)
	}
}

func (t *sessionTable[T]) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = map[string]*trackedSession[T]{}
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

func (t *sessionTracker[T]) bind(id string) {
	if id == "" {
		return
	}
	if t.session != nil && t.session.id == id {
		t.sessionID = id
		return
	}
	if t.session != nil {
		t.session.release()
		t.session = nil
	}

	key := sessionKey(t.srcHost, id)
	sess := t.table.get(key)
	if sess == nil {
		sess = &trackedSession[T]{
			id:     id,
			key:    key,
			events: []T{},
			md:     t.md,
			remote: t.remote,
			h:      t.h,
			logger: t.logger,
			table:  t.table,
			spec:   t.spec,
		}
		t.table.put(sess)
	}
	sess.acquire()
	if len(t.local) > 0 {
		sess.append(t.local...)
		t.local = nil
	}
	t.session = sess
	t.sessionID = id
}

func (t *sessionTracker[T]) ensure() {
	if t.session != nil {
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
