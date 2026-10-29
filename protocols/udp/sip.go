package udp

import (
	"context"
	"log/slog"
	"net"
	"strconv"

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

// maxSIPPayload covers INVITEs with a full SDP offer (often > 1 KiB).
const maxSIPPayload = 4096

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
	Dropped        bool   `json:"dropped,omitempty"` // write the udp_reply_limit budget kept from leaving
	Error          string `json:"error,omitempty"`   // why a write failed to send
	Variant        string `json:"variant,omitempty"` // response variant on writes
	Visit          int    `json:"visit,omitempty"`   // source's visit number on writes

	// command "rtp": one summary frame per caller media stream (SSRC)
	SSRC        string `json:"ssrc,omitempty"`         // hex
	Codec       string `json:"codec,omitempty"`        // audio encoding name, e.g. PCMU
	Packets     int    `json:"packets,omitempty"`      // RTP packets received
	Lost        int    `json:"lost,omitempty"`         // gaps in the sequence numbers
	DurationMs  int    `json:"duration_ms,omitempty"`  // recorded audio length
	DTMF        string `json:"dtmf,omitempty"`         // RFC 4733 digits, in order
	PayloadHash string `json:"payload_hash,omitempty"` // SHA-256 of the stored WAV
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

// sipRecall remembers each source's last visit; tests swap it for a store
// with a fake clock.
var sipRecall = recall.Shared

// beginSIPVisit marks activity from ip in sipRecall and returns its visit
// (see sipproto.BeginVisit).
func beginSIPVisit(ip net.IP, logger interfaces.Logger) sipproto.Visit {
	return sipproto.BeginVisit(sipRecall, ip, logger)
}

// noteSIPVisit stores what the source did in this event.
func noteSIPVisit(ip net.IP, v sipproto.Visit, events []parsedSIP) {
	reads := make([]sipproto.VisitRead, 0, len(events))
	for _, e := range events {
		if e.Direction == "read" {
			reads = append(reads, sipproto.VisitRead{Command: e.Command, Path: e.Path, Username: e.Username, UserAgent: e.UserAgent})
		}
	}
	v.Note(ip, reads)
}

// sendSIPReply sends data (msg parsed) to src and returns its write frame,
// tagged with the visit. A reply the udp_reply_limit budget dropped is no
// error, but its frame is marked dropped; honeypots that cannot tell report
// every reply as sent.
func sendSIPReply(h interfaces.Honeypot, logger interfaces.Logger, src, dst *net.UDPAddr, visit sipproto.Visit, data []byte, msg sip.Message) (parsedSIP, error) {
	frame := sipDecoded("write", msg, data)
	if visit.Number > 0 {
		frame.Variant = visit.Variant.String()
		frame.Visit = visit.Number
	}
	sent, err := true, error(nil)
	if r, ok := h.(interfaces.UDPReplyReporter); ok {
		sent, err = r.ReplyUDPSent(src, dst, data)
	} else {
		err = h.ReplyUDP(src, dst, data)
	}
	if err != nil {
		frame.Error = err.Error()
		logger.Error("Failed to send SIP reply", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return frame, err
	}
	frame.Dropped = !sent
	return frame, nil
}

func logSIPRequest(logger interfaces.Logger, method string) {
	logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", method))
}

// sipResponder builds the UDP SIP replies; tests swap it for deterministic tags and nonces.
var sipResponder = sipproto.NewResponder()

// parseSIP parses one datagram, tolerating bare-LF lines. A complete
// datagram may also omit the empty line after the headers; a truncated one
// may not, as its end is not the end of the message. data is not modified.
func parseSIP(data []byte, complete bool) (sip.Message, error) {
	return parser.NewPacketParser(log.NewDefaultLogrusLogger()).ParseMessage(sipproto.NormalizeHeaders(data, complete))
}

// HandleSIP parses a UDP SIP datagram and answers it like a misconfigured
// Asterisk PBX (OPTIONS and REGISTER 200, INVITE 100/180 then 200 with SDP
// after a ringing delay; the first few INVITEs per source get 404).
// An INVITE (or a challenged REGISTER) opens a dialog keyed by source IP and Call-ID: later datagrams
// with that key (ACK, BYE, CANCEL, retransmits) join it, and the dialog is
// produced as one event when it ends (BYE or CANCEL answered, idle timeout,
// frame cap or table eviction). Any other datagram is one event of its own.
func HandleSIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSIPPayload))
	copy(payload, data[:len(payload)])
	truncated := len(data) > maxSIPPayload

	if len(payload) == 0 {
		return handleSIPDatagram(srcAddr, dstAddr, nil, parsedSIP{}, nil, sipproto.Visit{}, md, logger, h)
	}

	logger.Info("SIP UDP packet received",
		slog.String("handler", "sip"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
	)

	msg, err := parseSIP(payload, !truncated)
	frame := sipDecoded("read", msg, payload)
	frame.Truncated = truncated
	if err != nil {
		logger.Debug("Failed to parse SIP message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return handleSIPDatagram(srcAddr, dstAddr, nil, frame, err, sipproto.Visit{}, md, logger, h)
	}

	visit, handled, err := joinSIPDialog(ctx, srcAddr, dstAddr, msg, frame, md, logger, h)
	if handled {
		return err
	}
	if visit.Number == 0 {
		visit = beginSIPVisit(srcAddr.IP, logger)
	}
	return handleSIPDatagram(srcAddr, dstAddr, msg, frame, nil, visit, md, logger, h)
}

// joinSIPDialog hands a datagram to the open dialog of its source and
// Call-ID, opening one first when msg starts a dialog. handled is false when
// no dialog took the datagram. visit is the visit begun for a new dialog (a
// datagram joining one keeps the visit the dialog started with), else zero.
func joinSIPDialog(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, msg sip.Message, frame parsedSIP, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) (visit sipproto.Visit, handled bool, err error) {
	if frame.CallID == "" {
		return visit, false, nil
	}
	key := sipDialogKey(srcAddr, frame.CallID)
	d := sipDialogs.get(key)
	if req, ok := msg.(sip.Request); ok && d == nil && opensSIPDialog(req) {
		visit = beginSIPVisit(srcAddr.IP, logger)
		var evicted *sipDialog
		d, evicted = sipDialogs.open(key, func() *sipDialog {
			d := newSIPDialog(ctx, key, sipDialogs, srcAddr, dstAddr, md, logger, h)
			if req.Method() == sip.INVITE {
				d.reject = visit.RejectInvite(srcAddr.IP)
			}
			d.visit = visit
			return d
		})
		if evicted != nil {
			evicted.finish(connection.EndEvicted)
		}
	}
	if d == nil {
		return visit, false, nil
	}
	handled, err = d.handle(msg, frame)
	return visit, handled, err
}

// opensSIPDialog reports whether req starts a dialog: an INVITE, or a REGISTER
// that is challenged so its credentialed retry joins the same event. A known
// extension is challenged when sip.register_challenge is on. An unknown
// extension is challenged when sip.always_auth_reject is on; otherwise it
// gets a 404 and is an event of its own.
func opensSIPDialog(req sip.Request) bool {
	switch req.Method() {
	case sip.INVITE:
		return true
	case sip.REGISTER:
		if sipproto.Credentials(req) != "" {
			return false
		}
		if sipproto.UnknownExtension(req) {
			return sipproto.AlwaysAuthReject()
		}
		return sipproto.RegisterChallenge()
	}
	return false
}

// handleSIPDatagram answers a datagram outside any dialog and produces it as
// one event. parseErr is the parse failure for an unparsable datagram; visit
// picks the response variant.
func handleSIPDatagram(srcAddr, dstAddr *net.UDPAddr, msg sip.Message, frame parsedSIP, parseErr error, visit sipproto.Visit, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedSIP{}
	if frame.Payload != nil {
		events = append(events, frame)
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		noteSIPVisit(srcAddr.IP, visit, events)
		if err := h.ProduceUDP("sip", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSIP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	if parseErr != nil {
		endReason = connection.EndReadError
		return parseErr
	}
	req, ok := msg.(sip.Request)
	if !ok {
		return nil
	}
	logSIPRequest(logger, string(req.Method()))

	for _, resp := range sipResponder.Reply(req, srcAddr, dstAddr, visit.Variant) {
		frame, err := sendSIPReply(h, logger, srcAddr, dstAddr, visit, []byte(resp.String()), resp)
		events = append(events, frame)
		if err != nil {
			endReason = connection.EndWriteError
			return err
		}
	}
	return nil
}
