package udp

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"
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

// stopSIPTimer stops *t, if set, and clears it.
func stopSIPTimer(t *sipTimer) {
	if *t != nil {
		(*t).Stop()
		*t = nil
	}
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

// sipAnsweredHold is how long an answered, ACKed call stays open for its
// BYE (sip.answered_hold); tests swap it.
var sipAnsweredHold = sipproto.AnsweredHold

// sipRingDelay is how long an answered INVITE rings before the 200 OK; an
// instant answer is a honeypot tell. Tests swap it for a fixed value.
var sipRingDelay = func() time.Duration {
	return 2*time.Second + rand.N(4*time.Second)
}

// sipDialog collects the frames of one call (INVITE, ACK, BYE, retransmits) or
// of a challenged REGISTER and its retry, and produces them as one event when it ends.
//
// Methods named *Locked expect d.mu held. The timer callbacks (answer,
// referDone, resendFinal) and the datagram entry points (handle,
// handleMedia) take it themselves; finish must run without it.
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

	visit sipproto.Visit // response variant of the source's visit

	rec *sipRecording // caller media, once a 2xx with SDP was sent

	// INVITE server transaction
	reject       bool // answer the first INVITE with 404
	inviteSeq    uint32
	invite       sip.Request
	tag          string // To tag of the INVITE's responses
	last         []byte // latest response to the INVITE, replayed on retransmits
	ring         sipTimer
	ringGen      uint64
	pendingFinal sip.Response // the final response (200, or 486 when busy) sent when ringing ends

	// final response resends until ACK: 2xx per RFC 3261 §13.3.1.4,
	// non-2xx per §17.2.1 (Timer G, ended by Timer H)
	final      sip.Response
	finalBytes []byte
	finalEnd   string // endReason when the final response is never ACKed
	finalSent  bool   // the final response left at least once
	acked      bool
	resend     sipTimer
	interval   time.Duration
	waited     time.Duration

	// requests the honeypot sends in the call (REFER progress NOTIFYs)
	localSeq uint32 // CSeq of the last one; 0 before the first
	refer    sipTimer
	referGen uint64
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

// fullLocked reports whether the dialog reached maxSIPDialogFrames.
func (d *sipDialog) fullLocked() bool {
	return len(d.events) >= maxSIPDialogFrames
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
	if endReason == "" && d.fullLocked() {
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
	var seq uint32
	if cseq, ok := req.CSeq(); ok {
		seq = cseq.SeqNo
	}
	switch req.Method() {
	case sip.ACK:
		return d.ackLocked(), nil
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
		if d.answeredLocked() && d.tag != "" && sipToTag(req) == d.tag {
			return d.reInviteLocked(seq, req)
		}
		return d.inviteLocked(seq, req)
	case sip.CANCEL:
		if d.pendingFinal != nil {
			return d.cancelLocked(req)
		}
	case sip.REFER:
		if d.answeredLocked() {
			return d.referLocked(req)
		}
	}

	logSIPRequest(d.logger, string(req.Method()))
	for _, resp := range sipResponder.Reply(req, d.src, d.dst, d.visit.Variant) {
		if err := d.respondLocked(resp); err != nil {
			return connection.EndWriteError, err
		}
	}

	switch req.Method() {
	case sip.BYE, sip.CANCEL:
		return connection.EndClientClose, nil
	case sip.REGISTER:
		// the credentialed retry completes the registration
		if sipproto.Credentials(req) != "" {
			return connection.EndHandlerClose, nil
		}
	}
	return "", nil
}

// ackLocked stops the final response resends and returns the endReason when
// the ACK completes a failed call.
func (d *sipDialog) ackLocked() string {
	if d.final == nil || d.acked {
		return ""
	}
	d.acked = true
	stopSIPTimer(&d.resend)
	// an answered call now waits for its BYE (see armIdleLocked)
	d.armIdleLocked()
	// the ACK to a 404, 486 or 487 completes the failed call; after a
	// 401/407 the caller retries the INVITE with credentials in this dialog
	if !d.final.IsSuccess() && !isAuthChallenge(d.final) {
		return connection.EndClientClose
	}
	return ""
}

// inviteLocked answers a new INVITE: 100 Trying, then 404 when the dialog
// was picked for rejection, else 180 Ringing (183 Session Progress with SDP
// in the progress variant, which already starts the media recording) and the
// final response after sipRingDelay (200 OK, or 486 Busy Here in the busy
// variant). In the auth variant an INVITE without credentials gets a 401
// challenge instead.
func (d *sipDialog) inviteLocked(seq uint32, req sip.Request) (string, error) {
	logSIPRequest(d.logger, string(req.Method()))
	first := d.invite == nil
	d.stopRingLocked()
	stopSIPTimer(&d.resend)
	d.invite, d.inviteSeq, d.final, d.acked = req, seq, nil, false

	reject := first && d.reject
	if !reject && d.visit.Variant == sipproto.Auth && sipproto.Credentials(req) == "" {
		// Asterisk challenges without a 100 Trying
		d.sendFinalLocked(sipResponder.Challenge(req, d.src), connection.EndTimeout)
		return "", nil
	}

	trying, ringing, ok := sipResponder.Answer(req, d.src, d.dst, d.visit.Variant)
	if err := d.respondLocked(trying); err != nil {
		return connection.EndWriteError, err
	}
	if reject {
		// what Asterisk sends when no dialplan extension matches the number
		d.sendFinalLocked(sipResponder.Final(req, d.src, 404, "Not Found", ""), connection.EndTimeout)
		return "", nil
	}
	d.tag = sipToTag(ringing)
	ringingBytes := []byte(ringing.String())
	if err := d.writeLocked(ringingBytes, ringing); err != nil {
		return connection.EndWriteError, err
	}
	d.bindMediaLocked(ringing)
	d.last = ringingBytes
	d.pendingFinal = ok
	if d.visit.Variant == sipproto.Busy {
		d.pendingFinal = sipResponder.Final(req, d.src, 486, "Busy Here", d.tag)
	}
	d.ringGen++
	gen := d.ringGen
	d.ring = sipAfterFunc(sipRingDelay(), func() { d.answer(gen) })
	return "", nil
}

// cancelLocked ends a ringing INVITE: 200 OK to the CANCEL, then 487 to the
// INVITE, resent until the caller ACKs it (RFC 3261 §9.2).
func (d *sipDialog) cancelLocked(req sip.Request) (string, error) {
	logSIPRequest(d.logger, string(req.Method()))
	d.stopRingLocked()
	if err := d.respondLocked(sipResponder.Final(req, d.src, 200, "OK", d.tag)); err != nil {
		return connection.EndWriteError, err
	}
	terminated := sipResponder.Final(d.invite, d.src, 487, "Request Terminated", d.tag)
	// the caller hung up, so an unACKed 487 still ends as client_close
	d.sendFinalLocked(terminated, connection.EndClientClose)
	return "", nil
}

// answeredLocked reports whether the call was answered (a 2xx went out),
// ACKed or not.
func (d *sipDialog) answeredLocked() bool {
	return d.final != nil && d.final.IsSuccess()
}

// reInviteLocked answers a re-INVITE in the answered call (To tag ours) with
// 200 OK and the same SDP answer, resent until ACKed like the first 200,
// instead of ringing it as a new call.
func (d *sipDialog) reInviteLocked(seq uint32, req sip.Request) (string, error) {
	logSIPRequest(d.logger, "re-INVITE")
	ok := sipResponder.ReInviteOK(req, d.src, d.final)
	d.invite, d.inviteSeq = req, seq
	d.sendFinalLocked(ok, connection.EndTimeout)
	return "", nil
}

// referLocked accepts a transfer in the answered call: 202 Accepted, a
// NOTIFY with "100 Trying" at once and one with "200 OK" after
// sipRingDelay, as if the transfer target answered. Nothing is dialed; the
// Refer-To number is only recorded (called_number on the read frame). A
// REFER without Refer-To gets 400, as Asterisk answers it.
func (d *sipDialog) referLocked(req sip.Request) (string, error) {
	logSIPRequest(d.logger, string(req.Method()))
	if len(req.GetHeaders("Refer-To")) == 0 {
		if err := d.respondLocked(sipResponder.Final(req, d.src, 400, "Bad Request", d.tag)); err != nil {
			return connection.EndWriteError, err
		}
		return "", nil
	}
	if err := d.respondLocked(sipResponder.Final(req, d.src, 202, "Accepted", d.tag)); err != nil {
		return connection.EndWriteError, err
	}
	if err := d.notifyReferLocked(false); err != nil {
		return connection.EndWriteError, err
	}
	stopSIPTimer(&d.refer)
	d.referGen++
	gen := d.referGen
	d.refer = sipAfterFunc(sipRingDelay(), func() { d.referDone(gen) })
	return "", nil
}

// notifyReferLocked sends the REFER progress NOTIFY (see
// sipproto.Responder.ReferNotify) to the packet source.
func (d *sipDialog) notifyReferLocked(done bool) error {
	if d.localSeq == 0 {
		d.localSeq = rand.Uint32N(0x7fff)
	}
	d.localSeq++
	notify := sipResponder.ReferNotify(d.invite, d.final, d.dst, "UDP", d.localSeq, done)
	if notify == nil {
		return nil
	}
	return d.respondLocked(notify)
}

// referDone fires when the pretend transfer target answers and sends the
// final NOTIFY. gen ties it to the REFER that started it.
func (d *sipDialog) referDone(gen uint64) {
	d.mu.Lock()
	if d.produced || gen != d.referGen {
		d.mu.Unlock()
		return
	}
	d.refer = nil
	endReason := ""
	if err := d.notifyReferLocked(true); err != nil {
		endReason = connection.EndWriteError
	} else if d.fullLocked() {
		endReason = connection.EndMaxFrames
	}
	d.mu.Unlock()

	if endReason != "" {
		d.finish(endReason)
	}
}

// answer fires when ringing ends and sends the final response. gen ties it
// to the INVITE that started the ringing.
func (d *sipDialog) answer(gen uint64) {
	d.mu.Lock()
	if d.produced || gen != d.ringGen || d.pendingFinal == nil {
		d.mu.Unlock()
		return
	}
	d.ring = nil
	final := d.pendingFinal
	d.pendingFinal = nil
	// the final response resends run up to 64*T1 from here
	d.armIdleLocked()
	d.sendFinalLocked(final, connection.EndTimeout)
	full := d.fullLocked()
	d.mu.Unlock()

	if full {
		d.finish(connection.EndMaxFrames)
	}
}

func (d *sipDialog) stopRingLocked() {
	stopSIPTimer(&d.ring)
	d.pendingFinal = nil
}

// sendFinalLocked sends the INVITE's final response and resends it at T1
// backoff until an ACK arrives. unacked is the endReason if none does. A
// failed send ends nothing: the resends retry it, and the call ends as
// write_error only if it never left (see resendFinal). A silent source (see
// sipproto.Visit.Silent) gets it once: the timer waits out the 64*T1 window
// in one step, so the unACKed count, the BYE after a 200 and the endReason
// stay the same without the resends.
func (d *sipDialog) sendFinalLocked(final sip.Response, unacked string) {
	data := []byte(final.String())
	d.finalSent = d.writeLocked(data, final) == nil
	d.bindMediaLocked(final)
	stopSIPTimer(&d.resend)
	d.last = data
	d.final = final
	d.finalBytes = data
	d.finalEnd = unacked
	d.acked = false
	d.interval = sipT1
	if d.visit.Silent(d.src.IP) {
		d.interval = 64 * sipT1
	}
	d.waited = 0
	d.resend = sipAfterFunc(d.interval, d.resendFinal)
}

func isAuthChallenge(res sip.Response) bool {
	code := res.StatusCode()
	return code == 401 || code == 407
}

func sipToTag(msg sip.Message) string {
	if to, ok := msg.To(); ok && to.Params != nil {
		if tag, ok := to.Params.Get("tag"); ok && tag != nil {
			return tag.String()
		}
	}
	return ""
}

// respondLocked sends msg to the caller and records it.
func (d *sipDialog) respondLocked(msg sip.Message) error {
	return d.writeLocked([]byte(msg.String()), msg)
}

// writeLocked sends data to the caller and records it. msg is the parsed
// form of data, or nil to re-parse it.
func (d *sipDialog) writeLocked(data []byte, msg sip.Message) error {
	if msg == nil {
		msg, _ = parseSIP(data, true)
	}
	frame, err := sendSIPReply(d.h, d.logger, d.src, d.dst, d.visit, data, msg)
	d.events = append(d.events, frame)
	return err
}

func (d *sipDialog) armIdleLocked() {
	stopSIPTimer(&d.idle)
	idle := sipIdleDuration()
	if d.acked && d.answeredLocked() {
		// dialers hang up answered calls minutes later; keep the BYE in
		// this event
		idle = max(idle, sipAnsweredHold())
	}
	d.idle = sipAfterFunc(idle, func() { d.finish(connection.EndTimeout) })
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
	switch {
	case d.waited >= 64*sipT1 && !d.finalSent:
		// the final response never left, so the caller's silence says
		// nothing about the tool
		endReason = connection.EndWriteError
	case d.waited >= 64*sipT1:
		endReason = d.finalEnd
		_ = d.visit.NoteUnacked(d.src.IP, int(d.final.StatusCode()), d.logger)
		if d.final.IsSuccess() {
			if bye := sipResponder.AckTimeoutBye(d.invite, d.final, d.dst, "UDP"); bye != nil {
				if err := d.respondLocked(bye); err != nil {
					endReason = connection.EndWriteError
				}
			}
		}
	default:
		// a failed resend is retried at the next interval
		if d.writeLocked(d.finalBytes, d.final) == nil {
			d.finalSent = true
		}
		if d.fullLocked() {
			endReason = connection.EndMaxFrames
		} else {
			d.interval = min(2*d.interval, sipT2)
			d.resend = sipAfterFunc(d.interval, d.resendFinal)
		}
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
	stopSIPTimer(&d.idle)
	stopSIPTimer(&d.resend)
	stopSIPTimer(&d.refer)
	d.stopRingLocked()
	if d.stopCtx != nil {
		d.stopCtx()
	}
	events := d.events
	md := d.md
	md.EndReason = endReason
	rec := d.rec
	d.mu.Unlock()

	if rec != nil {
		events = append(events, d.mediaFrames(rec, helpers.FirstOrEmpty[parsedSIP](events).CallID)...)
	}

	d.table.remove(d.key, d)
	noteSIPVisit(d.src.IP, d.visit, events)
	if err := d.h.ProduceUDP("sip", d.src, d.dst, md, helpers.FirstOrEmpty[parsedSIP](events).Payload, events); err != nil {
		d.logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
	}
}
