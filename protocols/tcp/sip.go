package tcp

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

const maxBufferSize = 1024

const (
	// sipMaxBody is the body kept per message; it covers INVITEs with a full
	// SDP offer (often > 1 KiB). Longer bodies are dropped and the frame is
	// truncated.
	sipMaxBody = 4096
	// maxSIPTCPFrames caps the frames kept per connection; reaching it ends
	// the connection with endReason max_frames.
	maxSIPTCPFrames = 64
	// maxSIPTCPCalls caps the INVITE calls tracked per connection; further
	// calls are answered at once, without ringing.
	maxSIPTCPCalls = 16
	// sipTCPAckTimeout is how long a final response to INVITE waits for its
	// ACK (64*T1, RFC 3261 §17.2.1). A reliable transport does not resend it.
	sipTCPAckTimeout = 64 * 500 * time.Millisecond
	// maxSIPTCPParked caps the ended connections held for a follow-up
	// connection (see sipParkTable); when it is full they produce at once.
	maxSIPTCPParked = 256
)

type parsedSIP struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // request method
	Path      string `json:"path,omitempty"`    // Request-URI
	Status    string `json:"status,omitempty"`  // response code on writes
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	UserAgent string `json:"user_agent,omitempty"` // User-Agent (reads) or Server (writes)
	Username  string `json:"username,omitempty"`   // digest Authorization username
	// CalledNumber is the dialed number of a request (Request-URI user, else To user)
	CalledNumber string `json:"called_number,omitempty"`
	// Tool is the fingerprinted scanner/dialer behind a read frame
	Tool string `json:"tool,omitempty"`
	// Digest auth a read frame carried; the honeypot issued the nonce, so
	// these crack the guessed password offline (hashcat -m 11400).
	Realm          string `json:"realm,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	DigestURI      string `json:"digest_uri,omitempty"`
	DigestResponse string `json:"digest_response,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	Qop            string `json:"qop,omitempty"`
	Nc             string `json:"nc,omitempty"`
	CNonce         string `json:"cnonce,omitempty"`
	Payload        []byte `json:"payload,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
	Variant        string `json:"variant,omitempty"` // response variant on writes
	Visit          int    `json:"visit,omitempty"`   // source's visit number on writes
}

// sipRecall remembers each source's last visit, shared with UDP SIP under
// the same "sip" key; tests swap it for a store with a fake clock.
var sipRecall = recall.Shared

// sipTimer is the part of *time.Timer the handler uses.
type sipTimer interface {
	Stop() bool
}

// sipTCPAfterFunc schedules call timers (ringing, ACK wait); tests swap it
// for a fake they fire by hand.
var sipTCPAfterFunc = func(d time.Duration, f func()) sipTimer {
	return time.AfterFunc(d, f)
}

// sipTCPRingDelay is how long an answered INVITE rings before the final
// response; an instant answer is a honeypot tell. Tests swap it.
var sipTCPRingDelay = func() time.Duration {
	return 2*time.Second + rand.N(4*time.Second)
}

// sipTCPParkHold is how long a connection that ended with a call still open
// waits for the caller to carry the call on over a new connection (see
// sipParkTable); tests swap it.
var sipTCPParkHold = sessionIdleDuration

// sipTCPAnsweredHold is how long a connection waits instead when a call on
// it was answered and ACKed, so the BYE minutes later joins the call
// (sip.answered_hold); tests swap it.
var sipTCPAnsweredHold = sipproto.AnsweredHold

// sipCall is the INVITE server transaction of one Call-ID on a connection.
type sipCall struct {
	reject       bool // answer the first INVITE with 404
	invite       sip.Request
	inviteSeq    uint32
	tag          string       // To tag of the INVITE's responses
	last         sip.Response // latest response to the INVITE, replayed on retransmits
	ring         sipTimer
	ringGen      uint64
	pendingFinal sip.Response // the final response sent when ringing ends
	final        sip.Response
	acked        bool
	ack          sipTimer // waits sipTCPAckTimeout for the ACK to final
}

func (c *sipCall) stopRing() {
	if c.ring != nil {
		c.ring.Stop()
		c.ring = nil
	}
	c.pendingFinal = nil
}

func (c *sipCall) stopAck() {
	if c.ack != nil {
		c.ack.Stop()
		c.ack = nil
	}
}

// sipRead is one message (or error) from the connection's reader goroutine.
type sipRead struct {
	msg sipproto.StreamMessage
	err error
	// timeout is set when the connection timeout could not be updated
	timeout bool
}

type sipServer struct {
	events    []parsedSIP
	conn      net.Conn
	logger    interfaces.Logger
	responder *sipproto.Responder
	srcIP     net.IP
	transport string // Via transport of requests the honeypot sends: TCP or TLS
	visit     sipproto.Visit
	started   bool // visit begun
	calls     map[string]*sipCall
	pingLF    int // LFs of the keepalive run so far; "\r\n\r\n" gets a pong
	// timers carries fired timer callbacks to the handler goroutine, which
	// owns all state; done stops senders once the handler returns.
	timers chan func() (string, error)
	done   chan struct{}
	// origin is the first connection of a call carried on over several
	// connections; the event takes its start time and source port.
	origin *sipOrigin
}

type sipOrigin struct {
	md     connection.Metadata
	remote net.Addr
}

// openCallIDs returns the Call-IDs whose final response was sent and that the
// caller may still continue: an unACKed final, or an answered call not yet
// ended by BYE.
func (s *sipServer) openCallIDs() []string {
	var ids []string
	for id, c := range s.calls {
		if id != "" && c.final != nil && (!c.acked || c.final.IsSuccess()) {
			ids = append(ids, id)
		}
	}
	return ids
}

// produce emits the connection's event; for a call carried on from parked
// connections it keeps the first connection's start and source address.
func (s *sipServer) produce(conn net.Conn, md connection.Metadata, h interfaces.Honeypot) {
	s.note()
	if s.origin != nil {
		md, conn = s.origin.withEnd(md.EndReason), &remoteAddrConn{Conn: conn, remote: s.origin.remote}
	}
	if err := h.ProduceTCP("sip", conn, md, helpers.FirstOrEmpty[parsedSIP](s.events).Payload, s.events); err != nil {
		s.logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
	}
}

func (o *sipOrigin) withEnd(endReason string) connection.Metadata {
	md := o.md
	md.EndReason = endReason
	return md
}

// sipParkable reports whether a connection that ended this way may be
// continued by the caller: it hung up or went quiet, rather than the
// honeypot ending it.
func sipParkable(endReason string) bool {
	switch endReason {
	case connection.EndClientClose, connection.EndClientReset, connection.EndReadError, connection.EndTimeout:
		return true
	}
	return false
}

// sipParkedConn is a connection that ended with calls still open.
type sipParkedConn struct {
	server *sipServer
	conn   net.Conn // closed; ProduceTCP still reads its addresses
	md     connection.Metadata
	h      interfaces.Honeypot
	keys   []string
	timer  sipTimer
}

// sipParkTable holds connections that ended with a call still open, keyed
// by source IP and Call-ID. Some dialers (the OpenSIPS "SIP Scan Call"
// fleet) close the connection after the 200 OK and send the ACK, or later
// the BYE, over a new one, as RFC 3261 section 18 allows; the new connection
// takes the parked one over, so the call stays one event. A parked
// connection nobody takes produces after sipTCPParkHold, or
// sipTCPAnsweredHold when it holds an answered, ACKed call.
type sipParkTable struct {
	mu    sync.Mutex
	byKey map[string]*sipParkedConn
	count int
}

var sipParked = newSIPParkTable()

func newSIPParkTable() *sipParkTable {
	return &sipParkTable{byKey: map[string]*sipParkedConn{}}
}

func sipParkKey(ip net.IP, callID string) string {
	return ip.String() + "|" + callID
}

// park holds the ended connection when its source left calls open. It
// returns false when the connection should produce now instead.
func (t *sipParkTable) park(s *sipServer, conn net.Conn, md connection.Metadata, h interfaces.Honeypot) bool {
	if s.srcIP == nil || !sipParkable(md.EndReason) {
		return false
	}
	ids := s.openCallIDs()
	if len(ids) == 0 {
		return false
	}
	hold := sipTCPParkHold()
	for _, id := range ids {
		if c := s.calls[id]; c.acked && c.final.IsSuccess() {
			hold = max(hold, sipTCPAnsweredHold())
		}
	}
	p := &sipParkedConn{server: s, conn: conn, md: md, h: h}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count >= maxSIPTCPParked {
		return false
	}
	for _, id := range ids {
		key := sipParkKey(s.srcIP, id)
		if t.byKey[key] != nil {
			// another ended connection already waits for this call
			return false
		}
		p.keys = append(p.keys, key)
	}
	for _, key := range p.keys {
		t.byKey[key] = p
	}
	t.count++
	p.timer = sipTCPAfterFunc(hold, func() { t.expire(p) })
	return true
}

// take removes and returns the connection parked for ip's call, or nil.
func (t *sipParkTable) take(ip net.IP, callID string) *sipParkedConn {
	t.mu.Lock()
	p := t.byKey[sipParkKey(ip, callID)]
	if p != nil {
		t.removeLocked(p)
	}
	t.mu.Unlock()
	if p != nil {
		p.timer.Stop()
	}
	return p
}

// expire produces p when no connection took it over.
func (t *sipParkTable) expire(p *sipParkedConn) {
	t.mu.Lock()
	parked := len(p.keys) > 0 && t.byKey[p.keys[0]] == p
	if parked {
		t.removeLocked(p)
	}
	t.mu.Unlock()
	if parked {
		p.server.produce(p.conn, p.md, p.h)
	}
}

func (t *sipParkTable) removeLocked(p *sipParkedConn) {
	for _, key := range p.keys {
		if t.byKey[key] == p {
			delete(t.byKey, key)
		}
	}
	t.count--
}

// adopt continues the calls of a parked connection on this one: its frames
// come first in this connection's event, and an unACKed final waits for its
// ACK here (an unACKed 200 OK is hung up over this connection).
func (s *sipServer) adopt(p *sipParkedConn) {
	s.events = append(p.server.events, s.events...)
	s.origin = p.server.origin
	if s.origin == nil {
		s.origin = &sipOrigin{md: p.md, remote: p.conn.RemoteAddr()}
	}
	for id, c := range p.server.calls {
		if _, ok := s.calls[id]; ok || c.final == nil || len(s.calls) >= maxSIPTCPCalls {
			continue
		}
		s.calls[id] = c
		if !c.acked {
			final := c.final
			c.ack = s.after(sipTCPAckTimeout, func() (string, error) { return s.ackTimeout(c, final) })
		}
	}
}

// begin picks the response variant once per connection (see
// sipproto.BeginVisit).
func (s *sipServer) begin() {
	if s.started {
		return
	}
	s.started = true
	s.visit = sipproto.BeginVisit(sipRecall, s.srcIP, s.logger)
}

// note stores what the source did on this connection.
func (s *sipServer) note() {
	reads := make([]sipproto.VisitRead, 0, len(s.events))
	for _, e := range s.events {
		if e.Direction == "read" {
			reads = append(reads, sipproto.VisitRead{Command: e.Command, Path: e.Path, Username: e.Username, UserAgent: e.UserAgent})
		}
	}
	s.visit.Note(s.srcIP, reads)
}

func remoteIP(conn net.Conn) net.IP {
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

func sipDecoded(direction string, msg sip.Message, payload []byte) parsedSIP {
	frame := parsedSIP{Direction: direction, Payload: payload}
	if msg == nil {
		return frame
	}
	info := sipproto.Describe(msg)
	frame.Command = info.Method
	frame.Path = info.URI
	if info.Status != 0 {
		frame.Status = strconv.Itoa(info.Status)
	}
	frame.From = info.From
	frame.To = info.To
	frame.CallID = info.CallID
	frame.UserAgent = info.UserAgent
	frame.Username = info.Username
	frame.CalledNumber = info.CalledNumber
	frame.Tool = info.Tool
	frame.Realm = info.Digest.Realm
	frame.Nonce = info.Digest.Nonce
	frame.DigestURI = info.Digest.URI
	frame.DigestResponse = info.Digest.Response
	frame.Algorithm = info.Digest.Algorithm
	frame.Qop = info.Digest.Qop
	frame.Nc = info.Digest.Nc
	frame.CNonce = info.Digest.CNonce
	return frame
}

// write sends msg (a response, or the honeypot's own BYE) and records it.
func (s *sipServer) write(msg sip.Message) error {
	data := []byte(msg.String())
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame := sipDecoded("write", msg, data)
	frame.Variant, frame.Visit = s.visit.Variant.String(), s.visit.Number
	s.events = append(s.events, frame)
	return nil
}

// after runs f on the handler goroutine once d has passed.
func (s *sipServer) after(d time.Duration, f func() (string, error)) sipTimer {
	return sipTCPAfterFunc(d, func() {
		select {
		case s.timers <- f:
		case <-s.done:
		}
	})
}

func (s *sipServer) stopTimers() {
	for _, c := range s.calls {
		c.stopRing()
		c.stopAck()
	}
}

// readLoop frames messages off conn until a read fails or the handler
// returns.
func (s *sipServer) readLoop(ctx context.Context, h interfaces.Honeypot, reads chan<- sipRead) {
	r := bufio.NewReader(s.conn)
	for {
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			select {
			case reads <- sipRead{err: err, timeout: true}:
			case <-s.done:
			}
			return
		}
		msg, err := sipproto.ReadStreamMessage(r, sipMaxBody)
		select {
		case reads <- sipRead{msg: msg, err: err}:
		case <-s.done:
			return
		}
		if err != nil {
			return
		}
	}
}

// HandleSIP takes a net.Conn and answers SIP like a misconfigured Asterisk
// PBX: OPTIONS and REGISTER get 200, INVITE rings (100, 180) and is answered
// with 200 and SDP after a ringing delay. Messages are framed by
// Content-Length, so one connection can carry several, split or pipelined.
func HandleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleSIP(ctx, conn, md, logger, h, sipproto.NewResponder())
}

func handleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, responder *sipproto.Responder) error {
	server := &sipServer{
		events:    []parsedSIP{},
		conn:      conn,
		logger:    logger,
		responder: responder,
		srcIP:     remoteIP(conn),
		transport: "TCP",
		calls:     map[string]*sipCall{},
		timers:    make(chan func() (string, error)),
		done:      make(chan struct{}),
	}
	if md.TLS != nil {
		server.transport = "TLS"
	}
	endReason := connection.EndHandlerClose
	defer func() {
		close(server.done)
		server.stopTimers()
		md.EndReason = endReason
		if !sipParked.park(server, conn, md, h) {
			server.produce(conn, md, h)
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SIP connection", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	reads := make(chan sipRead)
	go server.readLoop(ctx, h, reads)
	pp := parser.NewPacketParser(log.NewDefaultLogrusLogger())

	for {
		var (
			end string
			err error
		)
		select {
		case <-ctx.Done():
			return nil
		case f := <-server.timers:
			end, err = f()
		case r := <-reads:
			if r.timeout {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", "sip"), producer.ErrAttr(r.err))
				endReason = connection.EndTimeout
				return nil
			}
			if r.err != nil {
				if len(r.msg.Raw) > 0 {
					server.events = append(server.events, parsedSIP{Direction: "read", Payload: r.msg.Raw, Truncated: r.msg.Truncated})
				}
				logger.Debug("Failed to read data", slog.String("protocol", "sip"), producer.ErrAttr(r.err))
				endReason = connection.EndReasonFromRead(r.err)
				return nil
			}
			end, err = server.handle(pp, r.msg)
		}
		if end == "" && len(server.events) >= maxSIPTCPFrames {
			end = connection.EndMaxFrames
		}
		if end != "" {
			endReason = end
			return err
		}
	}
}

// handle records one framed message and answers it. It returns the
// endReason when the connection should end.
func (s *sipServer) handle(pp *parser.PacketParser, m sipproto.StreamMessage) (string, error) {
	if m.Keepalive {
		// RFC 5626 §4.4.1: a "\r\n\r\n" ping gets a "\r\n" pong
		s.pingLF += bytes.Count(m.Raw, []byte("\n"))
		if s.pingLF >= 2 {
			s.pingLF = 0
			if _, err := s.conn.Write([]byte("\r\n")); err != nil {
				return connection.EndWriteError, err
			}
		}
		return "", nil
	}
	s.pingLF = 0

	// bare-LF lines are accepted; the framer found the header end
	msg, err := pp.ParseMessage(sipproto.NormalizeHeaders(m.Raw, false))
	if err != nil {
		s.logger.Debug("Failed to parse SIP message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		msg = nil
	}
	frame := sipDecoded("read", msg, m.Raw)
	frame.Truncated = m.Truncated
	s.events = append(s.events, frame)

	req, ok := msg.(sip.Request)
	if !ok {
		return "", nil
	}
	s.logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
	s.begin()
	if s.srcIP != nil && frame.CallID != "" && s.calls[frame.CallID] == nil {
		if p := sipParked.take(s.srcIP, frame.CallID); p != nil {
			s.adopt(p)
		}
	}

	seq := uint32(0)
	if cseq, ok := req.CSeq(); ok {
		seq = cseq.SeqNo
	}
	c := s.calls[frame.CallID]
	switch req.Method() {
	case sip.ACK:
		if c != nil && c.final != nil && !c.acked {
			c.acked = true
			c.stopAck()
		}
		return "", nil
	case sip.INVITE:
		if c != nil && c.invite != nil && seq == c.inviteSeq {
			// a retransmitted INVITE gets the latest response again
			if c.last != nil {
				return s.writeOrEnd(c.last)
			}
			return "", nil
		}
		if c != nil || len(s.calls) < maxSIPTCPCalls {
			return s.invite(c, frame.CallID, seq, req)
		}
	case sip.CANCEL:
		if c != nil && c.pendingFinal != nil {
			return s.cancel(c, req)
		}
	case sip.BYE:
		if c != nil {
			// a late ACK timer must not hang up the ended call
			c.stopRing()
			c.stopAck()
			c.final = nil
			delete(s.calls, frame.CallID)
		}
	}

	for _, resp := range s.responder.Reply(req, s.conn.RemoteAddr(), s.conn.LocalAddr(), s.visit.Variant) {
		if end, err := s.writeOrEnd(resp); end != "" {
			return end, err
		}
	}
	return "", nil
}

func (s *sipServer) writeOrEnd(msg sip.Message) (string, error) {
	if err := s.write(msg); err != nil {
		s.logger.Error("Failed to write SIP reply", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return connection.EndWriteError, err
	}
	return "", nil
}

// invite answers a new INVITE (c is nil for a new Call-ID): 100 Trying, then
// 404 when the call was picked for rejection, else 180 Ringing (183 Session
// Progress with SDP in the progress variant) and the final response after
// sipTCPRingDelay (200 OK, or 486 Busy Here in the busy variant). In the
// auth variant an INVITE without credentials gets a 401 challenge instead.
func (s *sipServer) invite(c *sipCall, callID string, seq uint32, req sip.Request) (string, error) {
	first := c == nil
	if first {
		c = &sipCall{reject: s.visit.RejectInvite(s.srcIP)}
		s.calls[callID] = c
	}
	c.stopRing()
	c.stopAck()
	c.invite, c.inviteSeq, c.final, c.acked = req, seq, nil, false
	src, local := s.conn.RemoteAddr(), s.conn.LocalAddr()

	reject := first && c.reject
	if !reject && s.visit.Variant == sipproto.Auth && sipproto.Credentials(req) == "" {
		// Asterisk challenges without a 100 Trying
		return s.sendFinal(c, s.responder.Challenge(req, src))
	}
	trying, ringing, ok := s.responder.Answer(req, src, local, s.visit.Variant)
	if end, err := s.writeOrEnd(trying); end != "" {
		return end, err
	}
	if reject {
		// what Asterisk sends when no dialplan extension matches the number
		return s.sendFinal(c, s.responder.Final(req, src, 404, "Not Found", ""))
	}
	if end, err := s.writeOrEnd(ringing); end != "" {
		return end, err
	}
	c.tag = sipToTag(ringing)
	c.last = ringing
	c.pendingFinal = ok
	if s.visit.Variant == sipproto.Busy {
		c.pendingFinal = s.responder.Final(req, src, 486, "Busy Here", c.tag)
	}
	c.ringGen++
	gen := c.ringGen
	c.ring = s.after(sipTCPRingDelay(), func() (string, error) { return s.answer(c, gen) })
	return "", nil
}

// answer runs when ringing ends and sends the final response. gen ties it
// to the INVITE that started the ringing.
func (s *sipServer) answer(c *sipCall, gen uint64) (string, error) {
	if gen != c.ringGen || c.pendingFinal == nil {
		return "", nil
	}
	final := c.pendingFinal
	c.ring, c.pendingFinal = nil, nil
	return s.sendFinal(c, final)
}

// cancel ends a ringing INVITE: 200 OK to the CANCEL, then 487 to the
// INVITE (RFC 3261 §9.2).
func (s *sipServer) cancel(c *sipCall, req sip.Request) (string, error) {
	c.stopRing()
	src := s.conn.RemoteAddr()
	if end, err := s.writeOrEnd(s.responder.Final(req, src, 200, "OK", c.tag)); end != "" {
		return end, err
	}
	return s.sendFinal(c, s.responder.Final(c.invite, src, 487, "Request Terminated", c.tag))
}

// sendFinal sends the INVITE's final response and waits sipTCPAckTimeout
// for its ACK.
func (s *sipServer) sendFinal(c *sipCall, final sip.Response) (string, error) {
	if end, err := s.writeOrEnd(final); end != "" {
		return end, err
	}
	c.stopAck()
	c.last, c.final, c.acked = final, final, false
	c.ack = s.after(sipTCPAckTimeout, func() (string, error) { return s.ackTimeout(c, final) })
	return "", nil
}

// ackTimeout runs when final was not ACKed in time: it counts towards
// escalating the source's variant (the next call on this connection already
// gets the next one, as a new UDP dialog would), and an unACKed 200 OK is
// hung up with a BYE, as Asterisk (pjsip) does. The connection stays open.
func (s *sipServer) ackTimeout(c *sipCall, final sip.Response) (string, error) {
	if c.final != final || c.acked {
		return "", nil
	}
	c.ack = nil
	// the BYE still carries the variant that answered the call
	escalate := s.visit.NoteUnacked(s.srcIP, int(final.StatusCode()), s.logger)
	defer func() {
		if escalate {
			s.visit.Variant = sipproto.Escalate(s.visit.Variant, 1)
		}
	}()
	if !final.IsSuccess() {
		return "", nil
	}
	if bye := s.responder.AckTimeoutBye(c.invite, final, s.conn.LocalAddr(), s.transport); bye != nil {
		return s.writeOrEnd(bye)
	}
	return "", nil
}

func sipToTag(res sip.Response) string {
	if to, ok := res.To(); ok && to.Params != nil {
		if tag, ok := to.Params.Get("tag"); ok && tag != nil {
			return tag.String()
		}
	}
	return ""
}
