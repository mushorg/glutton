package udp

import (
	"context"
	"log/slog"
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

	// INVITE 200 OK resends (RFC 3261 §13.3.1.4)
	inviteSeq uint32
	invite    sip.Request
	okMsg     sip.Response
	ok        []byte
	acked     bool
	resend    sipTimer
	interval  time.Duration
	waited    time.Duration
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
		d.acked = true
		d.stopResendLocked()
		return "", nil
	case sip.INVITE:
		// a retransmitted INVITE gets the same 200 OK again, as a real UAS's
		// transaction layer would, instead of a new To tag
		if d.ok != nil && seq == d.inviteSeq {
			if err := d.writeLocked(d.ok, nil); err != nil {
				return connection.EndWriteError, err
			}
			return "", nil
		}
	}

	d.logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
	for _, resp := range sipResponder.Reply(req, d.src) {
		respBytes := []byte(resp.String())
		if err := d.writeLocked(respBytes, resp); err != nil {
			return connection.EndWriteError, err
		}
		if req.Method() == sip.INVITE && resp.IsSuccess() {
			d.startResendLocked(seq, req, resp, respBytes)
		}
	}

	switch req.Method() {
	case sip.BYE, sip.CANCEL:
		return connection.EndClientClose, nil
	}
	return "", nil
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

func (d *sipDialog) startResendLocked(seq uint32, invite sip.Request, okMsg sip.Response, ok []byte) {
	d.stopResendLocked()
	d.inviteSeq = seq
	d.invite = invite
	d.okMsg = okMsg
	d.ok = ok
	d.acked = false
	d.interval = sipT1
	d.waited = 0
	d.resend = sipAfterFunc(d.interval, d.resendOK)
}

func (d *sipDialog) stopResendLocked() {
	if d.resend != nil {
		d.resend.Stop()
		d.resend = nil
	}
}

// resendOK fires on the resend timer: it sends the 200 OK again and doubles
// the interval up to T2. Once 64*T1 has passed without an ACK it hangs up
// with a BYE, as Asterisk (pjsip) does, and produces the dialog.
func (d *sipDialog) resendOK() {
	d.mu.Lock()
	d.resend = nil
	if d.produced || d.acked || d.ok == nil {
		d.mu.Unlock()
		return
	}
	d.waited += d.interval
	endReason := ""
	if d.waited >= 64*sipT1 {
		endReason = connection.EndTimeout
		if bye := sipResponder.AckTimeoutBye(d.invite, d.okMsg); bye != nil {
			if err := d.writeLocked([]byte(bye.String()), bye); err != nil {
				endReason = connection.EndWriteError
			}
		}
	} else if err := d.writeLocked(d.ok, nil); err != nil {
		endReason = connection.EndWriteError
	} else if len(d.events) >= maxSIPDialogFrames {
		endReason = connection.EndMaxFrames
	} else {
		d.interval = min(2*d.interval, sipT2)
		d.resend = sipAfterFunc(d.interval, d.resendOK)
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
