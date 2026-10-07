package udp

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"

	"github.com/ghettovoice/gosip/sip"
)

const (
	// sipT1 and sipT2 are the RFC 3261 §17.1.1.1 timer values. The INVITE
	// 200 OK is resent at T1, doubling up to T2, until an ACK arrives or
	// 64*T1 has passed (§13.3.1.4).
	sipT1 = 500 * time.Millisecond
	sipT2 = 4 * time.Second
	// maxSIPDialogFrames caps the frames kept per dialog; reaching it
	// produces the dialog with endReason max_frames.
	maxSIPDialogFrames = 32
	// maxSIPDialogs caps the open dialogs; when full, the least recently
	// active dialog is produced with endReason evicted. Worst case memory is
	// about maxSIPDialogs * maxSIPDialogFrames * maxSIPPayload (32 MiB).
	maxSIPDialogs = 256
	// defaultSIPRejectInvites is how many new INVITE dialogs per source get
	// 404 before calls are answered (config key sip.reject_invites). Toll-fraud
	// tools stop at the first prefix that rings, so a few failures make them
	// reveal more of their dial-prefix list.
	defaultSIPRejectInvites = 2
	// sipRejectWindow is how long a source's INVITE count lasts; after it a
	// returning scanner is rejected again.
	sipRejectWindow = time.Hour
	// maxSIPRejectSources caps the sources tracked for rejection; when full,
	// the source counted longest ago is dropped.
	maxSIPRejectSources = 4096
)

// sipTimer is the part of *time.Timer the dialog uses.
type sipTimer interface {
	Stop() bool
}

// sipAfterFunc schedules dialog timers (idle flush and 200 OK resends);
// tests swap it for a fake they fire by hand.
var sipAfterFunc = func(d time.Duration, f func()) sipTimer {
	return time.AfterFunc(d, f)
}

// sipIdle overrides the dialog idle timeout in tests. When zero, production
// uses conn_timeout (default 45s), but never less than 64*T1 so a caller that
// never ACKs still sees every 200 OK resend in one event.
var sipIdle time.Duration

func sipIdleDuration() time.Duration {
	if sipIdle > 0 {
		return sipIdle
	}
	idle := 45 * time.Second
	if secs := viper.GetInt("conn_timeout"); secs > 0 {
		idle = time.Duration(secs) * time.Second
	}
	return max(idle, 64*sipT1)
}

// sipRingDelay is how long an answered INVITE rings before the 200 OK; an
// instant answer is a honeypot tell. Tests swap it for a fixed value.
var sipRingDelay = func() time.Duration {
	return 2*time.Second + rand.N(4*time.Second)
}

// sipNow is the clock for the reject window; tests swap it.
var sipNow = time.Now

// sipRejectLimit overrides sip.reject_invites in tests when >= 0.
var sipRejectLimit = -1

func sipRejectInvites() int {
	if sipRejectLimit >= 0 {
		return sipRejectLimit
	}
	if viper.IsSet("sip.reject_invites") {
		return viper.GetInt("sip.reject_invites")
	}
	return defaultSIPRejectInvites
}

type sipRejectEntry struct {
	count int
	first time.Time
}

// sipRejectTable counts new INVITE dialogs per source IP within
// sipRejectWindow.
type sipRejectTable struct {
	mu      sync.Mutex
	max     int
	sources map[string]sipRejectEntry
}

func newSIPRejectTable(max int) *sipRejectTable {
	return &sipRejectTable{max: max, sources: map[string]sipRejectEntry{}}
}

// sipRejects decides which INVITEs are answered with 404.
var sipRejects = newSIPRejectTable(maxSIPRejectSources)

// reject counts a new INVITE dialog from ip and reports whether it is among
// the first limit of the current window.
func (t *sipRejectTable) reject(ip string, now time.Time, limit int) bool {
	if limit <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.sources[ip]
	if !ok || now.Sub(e.first) >= sipRejectWindow {
		if !ok && len(t.sources) >= t.max {
			oldest := ""
			for k, cand := range t.sources {
				if oldest == "" || cand.first.Before(t.sources[oldest].first) {
					oldest = k
				}
			}
			delete(t.sources, oldest)
		}
		e = sipRejectEntry{first: now}
	}
	e.count++
	t.sources[ip] = e
	return e.count <= limit
}

func sipDialogKey(src *net.UDPAddr, callID string) string {
	return src.IP.String() + "|" + callID
}

type sipDialogTable struct {
	mu      sync.Mutex
	max     int
	dialogs map[string]*sipDialog
	// clock orders dialogs by last activity for eviction
	clock atomic.Uint64
}

func newSIPDialogTable(max int) *sipDialogTable {
	return &sipDialogTable{max: max, dialogs: map[string]*sipDialog{}}
}

// sipDialogs tracks open UDP SIP dialogs across datagrams.
var sipDialogs = newSIPDialogTable(maxSIPDialogs)

func (t *sipDialogTable) get(key string) *sipDialog {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dialogs[key]
}

// open returns the dialog for key, creating it when absent. A full table
// first evicts its least recently active dialog, which the caller must
// finish.
func (t *sipDialogTable) open(key string, create func() *sipDialog) (d, evicted *sipDialog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.dialogs[key]; d != nil {
		return d, nil
	}
	if len(t.dialogs) >= t.max {
		for _, cand := range t.dialogs {
			if evicted == nil || cand.lastSeen() < evicted.lastSeen() {
				evicted = cand
			}
		}
		if evicted != nil {
			delete(t.dialogs, evicted.key)
		}
	}
	d = create()
	t.dialogs[key] = d
	return d, evicted
}

func (t *sipDialogTable) remove(key string, expected *sipDialog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.dialogs[key]; ok && current == expected {
		delete(t.dialogs, key)
	}
}

// sipDialog collects the frames of one call (INVITE, ACK, BYE, retransmits)
// and produces them as one event when it ends.
type sipDialog struct {
	mu       sync.Mutex
	key      string
	table    *sipDialogTable
	src, dst *net.UDPAddr
	md       connection.Metadata
	logger   interfaces.Logger
	h        interfaces.Honeypot
	events   []parsedSIP
	seen     uint64
	produced bool
	idle     sipTimer
	stopCtx  func() bool

	// INVITE server transaction
	reject    bool // answer the first INVITE with 404
	inviteSeq uint32
	invite    sip.Request
	tag       string // To tag of the INVITE's responses
	last      []byte // latest response to the INVITE, replayed on retransmits
	ring      sipTimer
	ringGen   uint64
	pendingOK sip.Response // the 200 OK sent when ringing ends

	// final response resends until ACK: 2xx per RFC 3261 §13.3.1.4,
	// non-2xx per §17.2.1 (Timer G, ended by Timer H)
	final      sip.Response
	finalBytes []byte
	finalEnd   string // endReason when the final response is never ACKed
	acked      bool
	resend     sipTimer
	interval   time.Duration
	waited     time.Duration
}

func newSIPDialog(ctx context.Context, key string, table *sipDialogTable, src, dst *net.UDPAddr, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) *sipDialog {
	d := &sipDialog{key: key, table: table, src: src, dst: dst, md: md, logger: logger, h: h, events: []parsedSIP{}, seen: table.clock.Add(1)}
	// flush open dialogs on shutdown
	d.stopCtx = context.AfterFunc(ctx, func() { d.finish(connection.EndHandlerClose) })
	return d
}

func (d *sipDialog) lastSeen() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen
}

// handle records one datagram of the dialog and answers it. It returns
// false when the dialog was already produced, so the caller handles the
// datagram on its own.
func (d *sipDialog) handle(msg sip.Message, frame parsedSIP) (bool, error) {
	d.mu.Lock()
	if d.produced {
		d.mu.Unlock()
		return false, nil
	}
	d.seen = d.table.clock.Add(1)
	d.events = append(d.events, frame)
	d.armIdleLocked()

	var err error
	endReason := ""
	if req, ok := msg.(sip.Request); ok {
		endReason, err = d.requestLocked(req)
	}
	if endReason == "" && len(d.events) >= maxSIPDialogFrames {
		endReason = connection.EndMaxFrames
	}
	d.mu.Unlock()

	if endReason != "" {
		d.finish(endReason)
	}
	return true, err
}

// requestLocked answers req and returns the endReason when req ends the dialog.
func (d *sipDialog) requestLocked(req sip.Request) (string, error) {
	seq := uint32(0)
	if cseq, ok := req.CSeq(); ok {
		seq = cseq.SeqNo
	}
	switch req.Method() {
	case sip.ACK:
		if d.final == nil || d.acked {
			return "", nil
		}
		d.acked = true
		d.stopResendLocked()
		// the ACK to a 404 or 487 completes the failed call
		if !d.final.IsSuccess() {
			return connection.EndClientClose, nil
		}
		return "", nil
	case sip.INVITE:
		// a retransmitted INVITE gets the latest response again (180 while
		// ringing, then the final), as a real UAS's transaction layer would,
		// instead of a new To tag
		if d.invite != nil && seq == d.inviteSeq {
			if d.last != nil {
				if err := d.writeLocked(d.last, nil); err != nil {
					return connection.EndWriteError, err
				}
			}
			return "", nil
		}
		return d.inviteLocked(seq, req)
	case sip.CANCEL:
		if d.pendingOK != nil {
			return d.cancelLocked(req)
		}
	}

	d.logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
	for _, resp := range sipResponder.Reply(req, d.src) {
		if err := d.writeLocked([]byte(resp.String()), resp); err != nil {
			return connection.EndWriteError, err
		}
	}

	switch req.Method() {
	case sip.BYE, sip.CANCEL:
		return connection.EndClientClose, nil
	}
	return "", nil
}

// inviteLocked answers a new INVITE: 100 Trying, then 404 when the dialog
// was picked for rejection, else 180 Ringing and the 200 OK after
// sipRingDelay.
func (d *sipDialog) inviteLocked(seq uint32, req sip.Request) (string, error) {
	d.logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
	first := d.invite == nil
	d.stopRingLocked()
	d.stopResendLocked()
	d.invite, d.inviteSeq, d.final, d.acked = req, seq, nil, false

	trying, ringing, ok := sipResponder.Answer(req, d.src)
	if err := d.writeLocked([]byte(trying.String()), trying); err != nil {
		return connection.EndWriteError, err
	}
	if first && d.reject {
		// what Asterisk sends when no dialplan extension matches the number
		notFound := sipResponder.Final(req, d.src, 404, "Not Found", "")
		return d.sendFinalLocked(notFound, connection.EndTimeout)
	}
	d.tag = sipToTag(ringing)
	ringingBytes := []byte(ringing.String())
	if err := d.writeLocked(ringingBytes, ringing); err != nil {
		return connection.EndWriteError, err
	}
	d.last = ringingBytes
	d.pendingOK = ok
	d.ringGen++
	gen := d.ringGen
	d.ring = sipAfterFunc(sipRingDelay(), func() { d.answer(gen) })
	return "", nil
}

// cancelLocked ends a ringing INVITE: 200 OK to the CANCEL, then 487 to the
// INVITE, resent until the caller ACKs it (RFC 3261 §9.2).
func (d *sipDialog) cancelLocked(req sip.Request) (string, error) {
	d.logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
	d.stopRingLocked()
	cancelOK := sipResponder.Final(req, d.src, 200, "OK", d.tag)
	if err := d.writeLocked([]byte(cancelOK.String()), cancelOK); err != nil {
		return connection.EndWriteError, err
	}
	terminated := sipResponder.Final(d.invite, d.src, 487, "Request Terminated", d.tag)
	// the caller hung up, so an unACKed 487 still ends as client_close
	return d.sendFinalLocked(terminated, connection.EndClientClose)
}

// answer fires when ringing ends and sends the 200 OK. gen ties it to the
// INVITE that started the ringing.
func (d *sipDialog) answer(gen uint64) {
	d.mu.Lock()
	if d.produced || gen != d.ringGen || d.pendingOK == nil {
		d.mu.Unlock()
		return
	}
	d.ring = nil
	ok := d.pendingOK
	d.pendingOK = nil
	// the 200 OK resends run up to 64*T1 from here
	d.armIdleLocked()
	endReason, _ := d.sendFinalLocked(ok, connection.EndTimeout)
	if endReason == "" && len(d.events) >= maxSIPDialogFrames {
		endReason = connection.EndMaxFrames
	}
	d.mu.Unlock()

	if endReason != "" {
		d.finish(endReason)
	}
}

func (d *sipDialog) stopRingLocked() {
	if d.ring != nil {
		d.ring.Stop()
		d.ring = nil
	}
	d.pendingOK = nil
}

// sendFinalLocked sends the INVITE's final response and resends it at T1
// backoff until an ACK arrives. unacked is the endReason if none does.
func (d *sipDialog) sendFinalLocked(final sip.Response, unacked string) (string, error) {
	data := []byte(final.String())
	if err := d.writeLocked(data, final); err != nil {
		return connection.EndWriteError, err
	}
	d.stopResendLocked()
	d.last = data
	d.final = final
	d.finalBytes = data
	d.finalEnd = unacked
	d.acked = false
	d.interval = sipT1
	d.waited = 0
	d.resend = sipAfterFunc(d.interval, d.resendFinal)
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

// writeLocked sends data to the caller and records it. msg is the parsed
// form of data, or nil to re-parse it.
func (d *sipDialog) writeLocked(data []byte, msg sip.Message) error {
	if msg == nil {
		msg, _ = parseSIP(data, true)
	}
	d.events = append(d.events, sipDecoded("write", msg, data))
	if err := d.h.ReplyUDP(d.src, d.dst, data); err != nil {
		d.logger.Error("Failed to send SIP reply", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return err
	}
	return nil
}

func (d *sipDialog) armIdleLocked() {
	if d.idle != nil {
		d.idle.Stop()
	}
	d.idle = sipAfterFunc(sipIdleDuration(), func() { d.finish(connection.EndTimeout) })
}

func (d *sipDialog) stopResendLocked() {
	if d.resend != nil {
		d.resend.Stop()
		d.resend = nil
	}
}

// resendFinal fires on the resend timer: it sends the final response again
// and doubles the interval up to T2. Once 64*T1 has passed without an ACK
// the dialog is produced; an unACKed 200 OK is first hung up with a BYE, as
// Asterisk (pjsip) does.
func (d *sipDialog) resendFinal() {
	d.mu.Lock()
	d.resend = nil
	if d.produced || d.acked || d.final == nil {
		d.mu.Unlock()
		return
	}
	d.waited += d.interval
	endReason := ""
	if d.waited >= 64*sipT1 {
		endReason = d.finalEnd
		if d.final.IsSuccess() {
			if bye := sipResponder.AckTimeoutBye(d.invite, d.final); bye != nil {
				if err := d.writeLocked([]byte(bye.String()), bye); err != nil {
					endReason = connection.EndWriteError
				}
			}
		}
	} else if err := d.writeLocked(d.finalBytes, d.final); err != nil {
		endReason = connection.EndWriteError
	} else if len(d.events) >= maxSIPDialogFrames {
		endReason = connection.EndMaxFrames
	} else {
		d.interval = min(2*d.interval, sipT2)
		d.resend = sipAfterFunc(d.interval, d.resendFinal)
	}
	d.mu.Unlock()

	if endReason != "" {
		d.finish(endReason)
	}
}

// finish produces the dialog once and removes it from the table.
func (d *sipDialog) finish(endReason string) {
	d.mu.Lock()
	if d.produced {
		d.mu.Unlock()
		return
	}
	d.produced = true
	if d.idle != nil {
		d.idle.Stop()
		d.idle = nil
	}
	d.stopResendLocked()
	d.stopRingLocked()
	if d.stopCtx != nil {
		d.stopCtx()
	}
	events := d.events
	md := d.md
	md.EndReason = endReason
	d.mu.Unlock()

	d.table.remove(d.key, d)
	if err := d.h.ProduceUDP("sip", d.src, d.dst, md, helpers.FirstOrEmpty[parsedSIP](events).Payload, events); err != nil {
		d.logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
	}
}
