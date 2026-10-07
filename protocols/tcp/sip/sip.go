// Package sip builds the honeypot's SIP replies and extracts the request
// fields recorded in decoded frames. It is shared by the TCP and UDP SIP
// handlers and does no I/O.
package sip

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	gosip "github.com/ghettovoice/gosip/sip"
)

const (
	// Persona: a misconfigured Asterisk PBX (chan_pjsip) whose endpoints need
	// no auth to register or place calls, so toll-fraud scanners move on from
	// extension discovery to dialing out.
	serverAgent = "Asterisk PBX 18.20.0"
	realm       = "asterisk"
	allowList   = "OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER"
	supported   = "100rel, timer, replaces, norefersub"

	// maxExpires is the longest registration granted (Asterisk default_expiration).
	maxExpires = 3600
	// RTP ports are drawn from Asterisk's default rtpstart/rtpend range.
	rtpPortBase  = 10000
	rtpPortSlots = 5000
)

// Responder builds replies to SIP requests. Token returns the random value
// used for To tags and digest nonces; replace it in tests for stable output.
type Responder struct {
	Token func() string
}

// NewResponder returns a Responder backed by crypto/rand.
func NewResponder() *Responder {
	return &Responder{Token: randomToken}
}

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Reply returns the responses to send for req, received from src, in order.
// A nil slice means no reply. The top Via of each response gets received/rport
// filled from src as a real proxy or UA would; src may be nil.
func (r *Responder) Reply(req gosip.Request, src net.Addr) []gosip.Response {
	return annotate(req, src, r.reply(req)...)
}

// Answer returns the 100 Trying, 180 Ringing and 200 OK (with SDP) for an
// INVITE, Via annotated for src like Reply. The UDP handler sends the 200
// after a ringing delay instead of in the same burst.
func (r *Responder) Answer(req gosip.Request, src net.Addr) (trying, ringing, ok gosip.Response) {
	resps := annotate(req, src, r.invite(req)...)
	return resps[0], resps[1], resps[2]
}

// Final returns a response to req with code and reason, Via annotated for
// src like Reply. tag is the To tag; empty draws a new one. Responses that
// belong to an INVITE already answered with a provisional (487, and the 200
// to its CANCEL) pass that response's tag (RFC 3261 §9.2).
func (r *Responder) Final(req gosip.Request, src net.Addr, code gosip.StatusCode, reason, tag string) gosip.Response {
	if tag == "" {
		tag = r.Token()
	}
	return annotate(req, src, r.response(req, code, reason, tag))[0]
}

// annotate sets the top Via of each response from src (see sourceVia).
func annotate(req gosip.Request, src net.Addr, resps ...gosip.Response) []gosip.Response {
	if vias, ok := sourceVia(req, src); ok {
		for _, res := range resps {
			res.ReplaceHeaders("Via", vias)
		}
	}
	return resps
}

// sourceVia returns req's Via headers with the top hop annotated for src:
// rport gets the source port when the client asked for it (RFC 3581 §4), and
// received is added when the client asked for rport or its sent-by host is
// not the packet source (RFC 3261 §18.2.1).
func sourceVia(req gosip.Request, src net.Addr) ([]gosip.Header, bool) {
	if src == nil {
		return nil, false
	}
	host, port, err := net.SplitHostPort(src.String())
	if err != nil {
		return nil, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	hs := req.GetHeaders("Via")
	if len(hs) == 0 {
		return nil, false
	}
	top, ok := hs[0].(gosip.ViaHeader)
	if !ok || len(top) == 0 {
		return nil, false
	}
	top = top.Clone().(gosip.ViaHeader)
	hop := top[0]
	if hop.Params == nil {
		hop.Params = gosip.NewParams()
	}
	rport, wantsRport := hop.Params.Get("rport")
	changed := false
	if wantsRport && (rport == nil || rport.String() == "") {
		hop.Params.Add("rport", gosip.String{Str: port})
		changed = true
	}
	if sentBy := net.ParseIP(hop.Host); wantsRport || sentBy == nil || !sentBy.Equal(ip) {
		hop.Params.Add("received", gosip.String{Str: ip.String()})
		changed = true
	}
	if !changed {
		return nil, false
	}
	return append([]gosip.Header{top}, hs[1:]...), true
}

// reply returns the responses to send for req, in order. A nil slice means
// no reply (ACK, or a request the honeypot ignores).
//
// REGISTER is accepted with or without credentials, and INVITE is answered
// (100 Trying, 180 Ringing, 200 OK with an SDP answer), so scanners that probe
// an extension go on to place the toll-fraud call and reveal the dialed
// number. BYE ends that call with 200. Other session-creating requests
// (SUBSCRIBE, MESSAGE, ...) get a 401 digest challenge when unauthenticated
// and 403 Forbidden once they carry credentials.
func (r *Responder) reply(req gosip.Request) []gosip.Response {
	switch req.Method() {
	case gosip.ACK:
		return nil
	case gosip.OPTIONS:
		return []gosip.Response{r.response(req, 200, "OK", r.Token(),
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
			&gosip.GenericHeader{HeaderName: "Accept", Contents: "application/sdp"},
			&gosip.GenericHeader{HeaderName: "Supported", Contents: supported},
		)}
	case gosip.REGISTER:
		return []gosip.Response{r.register(req)}
	case gosip.INVITE:
		return r.invite(req)
	case gosip.BYE:
		return []gosip.Response{r.response(req, 200, "OK", r.Token())}
	case gosip.SUBSCRIBE, gosip.NOTIFY, gosip.PUBLISH,
		gosip.MESSAGE, gosip.REFER, gosip.UPDATE, gosip.INFO:
		if Credentials(req) != "" {
			return []gosip.Response{r.response(req, 403, "Forbidden", r.Token())}
		}
		challenge := `Digest realm="` + realm + `",nonce="` + r.Token() + `",algorithm=MD5,qop="auth"`
		return []gosip.Response{r.response(req, 401, "Unauthorized", r.Token(),
			&gosip.GenericHeader{HeaderName: "WWW-Authenticate", Contents: challenge},
		)}
	case gosip.CANCEL, gosip.PRACK:
		return []gosip.Response{r.response(req, 481, "Call/Transaction Does Not Exist", r.Token())}
	default:
		return []gosip.Response{r.response(req, 501, "Not Implemented", r.Token(),
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
		)}
	}
}

// register grants the binding: Contact headers are echoed with the granted
// expiry. Expires 0 (unregister) is acknowledged without a Contact.
func (r *Responder) register(req gosip.Request) gosip.Response {
	expires := requestedExpires(req)
	var extra []gosip.Header
	if expires > 0 {
		for _, h := range req.GetHeaders("Contact") {
			contact, ok := h.(*gosip.ContactHeader)
			if !ok || contact.Address == nil || contact.Address.IsWildcard() {
				continue
			}
			contact = contact.Clone().(*gosip.ContactHeader)
			if contact.Params == nil {
				contact.Params = gosip.NewParams()
			}
			contact.Params.Add("expires", gosip.String{Str: strconv.Itoa(expires)})
			extra = append(extra, contact)
		}
	}
	e := gosip.Expires(expires)
	extra = append(extra, &e)
	return r.response(req, 200, "OK", r.Token(), extra...)
}

// requestedExpires returns the Expires header value (or the first Contact
// expires param), defaulting to and capped at maxExpires.
func requestedExpires(req gosip.Request) int {
	value := ""
	if hs := req.GetHeaders("Expires"); len(hs) > 0 {
		value = hs[0].Value()
	} else if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		if contact, ok := hs[0].(*gosip.ContactHeader); ok && contact.Params != nil {
			if v, ok := contact.Params.Get("expires"); ok && v != nil {
				value = v.String()
			}
		}
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 || n > maxExpires {
		return maxExpires
	}
	return n
}

// invite answers the call. 100 Trying carries no To tag; 180 and 200 share
// one so they belong to the same dialog.
func (r *Responder) invite(req gosip.Request) []gosip.Response {
	host, port, user := localTarget(req)
	contact := "<sip:" + host + ":" + port + ">"
	if user != "" {
		contact = "<sip:" + user + "@" + host + ":" + port + ">"
	}
	tag := r.Token()
	session := r.Token()
	answer := sdpAnswer(string(req.Body()), host, rtpPort(session), sessionID(session))
	contentType := gosip.ContentType("application/sdp")

	ok := r.response(req, 200, "OK", tag,
		&gosip.GenericHeader{HeaderName: "Contact", Contents: contact},
		&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
		&gosip.GenericHeader{HeaderName: "Supported", Contents: supported},
		&contentType,
	)
	ok.SetBody(answer, true)
	return []gosip.Response{
		r.response(req, 100, "Trying", ""),
		r.response(req, 180, "Ringing", tag,
			&gosip.GenericHeader{HeaderName: "Contact", Contents: contact},
		),
		ok,
	}
}

// localTarget returns the host, port and user the caller addressed in the
// Request-URI; that is the honeypot's address as the scanner sees it.
func localTarget(req gosip.Request) (host, port, user string) {
	host, port = "0.0.0.0", "5060"
	uri := req.Recipient()
	if uri == nil {
		return host, port, ""
	}
	if ip := net.ParseIP(uri.Host()); ip != nil && ip.To4() != nil {
		host = ip.String()
	}
	if p := uri.Port(); p != nil {
		port = strconv.Itoa(int(*p))
	}
	if u := uri.User(); u != nil {
		user = u.String()
	}
	return host, port, user
}

func tokenValue(token string) uint64 {
	v, _ := strconv.ParseUint(token[:min(len(token), 8)], 16, 64)
	return v
}

// rtpPort picks an even port in Asterisk's default RTP range.
func rtpPort(token string) int {
	return rtpPortBase + 2*int(tokenValue(token)%rtpPortSlots)
}

func sessionID(token string) int {
	return int(tokenValue(token) % 1000000)
}

// offeredFormats returns the audio payload types offered in an SDP body and
// the payload type of telephone-event, if offered.
func offeredFormats(offer string) (formats []string, dtmf string) {
	for _, line := range strings.Split(offer, "\n") {
		line = strings.TrimSpace(line)
		if fields := strings.Fields(line); strings.HasPrefix(line, "m=audio ") && len(fields) > 3 {
			formats = fields[3:]
		}
		if rest, ok := strings.CutPrefix(line, "a=rtpmap:"); ok {
			if pt, enc, ok := strings.Cut(rest, " "); ok && strings.HasPrefix(strings.ToLower(enc), "telephone-event/") {
				dtmf = pt
			}
		}
	}
	return formats, dtmf
}

// sdpAnswer accepts PCMU, else PCMA, as Asterisk's default allow list does.
func sdpAnswer(offer, host string, port, session int) string {
	formats, dtmf := offeredFormats(offer)
	codec, name := "0", "PCMU"
	for _, f := range formats {
		if f == "0" {
			codec, name = "0", "PCMU"
			break
		}
		if f == "8" {
			codec, name = "8", "PCMA"
		}
	}
	media := codec
	if dtmf != "" {
		media += " " + dtmf
	}
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d %d IN IP4 %s", session, session+2, host),
		"s=Asterisk",
		"c=IN IP4 " + host,
		"t=0 0",
		fmt.Sprintf("m=audio %d RTP/AVP %s", port, media),
		fmt.Sprintf("a=rtpmap:%s %s/8000", codec, name),
	}
	if dtmf != "" {
		lines = append(lines, "a=rtpmap:"+dtmf+" telephone-event/8000", "a=fmtp:"+dtmf+" 0-16")
	}
	lines = append(lines, "a=ptime:20", "a=maxptime:150", "a=sendrecv")
	return strings.Join(lines, "\r\n") + "\r\n"
}

// response copies the dialog headers from req (RFC 3261 §8.2.6), adds tag to
// To unless it is empty or To already has one, and appends the persona
// Server header plus extra.
func (r *Responder) response(req gosip.Request, code gosip.StatusCode, reason, tag string, extra ...gosip.Header) gosip.Response {
	res := gosip.NewResponse("", req.SipVersion(), code, reason, []gosip.Header{}, "", req.Fields())
	gosip.CopyHeaders("Via", req, res)
	gosip.CopyHeaders("From", req, res)
	if to, ok := req.To(); ok {
		to = to.Clone().(*gosip.ToHeader)
		if to.Params == nil {
			to.Params = gosip.NewParams()
		}
		if tag != "" && !to.Params.Has("tag") {
			to.Params.Add("tag", gosip.String{Str: tag})
		}
		res.AppendHeader(to)
	}
	gosip.CopyHeaders("Call-ID", req, res)
	gosip.CopyHeaders("CSeq", req, res)
	res.AppendHeader(&gosip.GenericHeader{HeaderName: "Server", Contents: serverAgent})
	for _, h := range extra {
		res.AppendHeader(h)
	}
	res.SetBody("", true)
	return res
}

// Credentials returns the username from an Authorization or
// Proxy-Authorization header, or "" when the request is unauthenticated.
// Only the username is returned; the digest response is never extracted.
func Credentials(req gosip.Request) string {
	for _, name := range []string{"Authorization", "Proxy-Authorization"} {
		for _, h := range req.GetHeaders(name) {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.Value())), "digest") {
				continue
			}
			if user := gosip.AuthFromValue(h.Value()).Username(); user != "" {
				return user
			}
		}
	}
	return ""
}

// Info is the subset of a SIP message recorded in decoded frames.
type Info struct {
	Method    string
	Status    int
	URI       string
	From      string
	To        string
	CallID    string
	UserAgent string
	Username  string
}

// Describe extracts Info from a parsed request or response.
func Describe(msg gosip.Message) Info {
	var info Info
	switch m := msg.(type) {
	case gosip.Request:
		info.Method = string(m.Method())
		if uri := m.Recipient(); uri != nil {
			info.URI = uri.String()
		}
		info.Username = Credentials(m)
	case gosip.Response:
		info.Status = int(m.StatusCode())
	default:
		return info
	}
	if from, ok := msg.From(); ok && from.Address != nil {
		info.From = from.Address.String()
	}
	if to, ok := msg.To(); ok && to.Address != nil {
		info.To = to.Address.String()
	}
	if callID, ok := msg.CallID(); ok {
		info.CallID = callID.Value()
	}
	for _, name := range []string{"User-Agent", "Server"} {
		if hs := msg.GetHeaders(name); len(hs) > 0 {
			info.UserAgent = hs[0].Value()
			break
		}
	}
	return info
}

// NormalizeHeaders rewrites the header lines of a SIP message to end in CRLF,
// so the strict gosip parser accepts clients that end lines with a bare LF
// (real Asterisk does). The body after the first empty line is kept as is.
// With terminate set, a message with no empty line has its headers ended at
// the end of data: a datagram without Content-Length carries its body to the
// end of the packet (RFC 3261 section 18.3), so it may omit the empty line too.
// Well-formed CRLF messages come back byte-identical.
func NormalizeHeaders(data []byte, terminate bool) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, 0, len(data)+64)
	rest := data
	for len(rest) > 0 {
		line, tail, found := bytes.Cut(rest, []byte("\n"))
		if !found {
			if !terminate {
				return append(out, rest...)
			}
			out = append(out, bytes.TrimSuffix(line, []byte("\r"))...)
			return append(out, "\r\n\r\n"...)
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		out = append(append(out, line...), '\r', '\n')
		rest = tail
		if len(line) == 0 {
			return append(out, rest...)
		}
	}
	if terminate {
		out = append(out, '\r', '\n')
	}
	return out
}

// maxStartLine bounds how far LooksLikeSIP scans for the end of the start line.
const maxStartLine = 512

// LooksLikeSIP reports whether data starts with a SIP request line
// ("METHOD sip:... SIP/2.0") or status line ("SIP/2.0 200 OK"), ended by CRLF
// or a bare LF. The generic
// UDP handler uses it to route SIP sent to non-standard ports.
func LooksLikeSIP(data []byte) bool {
	line := data[:min(len(data), maxStartLine)]
	end := bytes.IndexByte(line, '\n')
	if end < 0 {
		return false
	}
	start := strings.TrimSuffix(string(line[:end]), "\r")
	if strings.HasPrefix(start, "SIP/2.0 ") {
		code, _, _ := strings.Cut(start[len("SIP/2.0 "):], " ")
		n, err := strconv.Atoi(code)
		return err == nil && len(code) == 3 && n >= 100 && n <= 699
	}
	parts := strings.Split(start, " ")
	if len(parts) != 3 || parts[2] != "SIP/2.0" || !isMethod(parts[0]) {
		return false
	}
	scheme, _, ok := strings.Cut(strings.ToLower(parts[1]), ":")
	return ok && (scheme == "sip" || scheme == "sips" || scheme == "tel")
}

func isMethod(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// ackTimeoutReason is the Reason header pjsip (and so Asterisk chan_pjsip)
// puts on the BYE it sends when a 2xx to INVITE is never ACKed: the INVITE
// transaction ends with 408 and add_reason_warning_hdr formats it as
// "SIP ;cause=%u ;text=\"%s\"" (pjsip-ua/sip_inv.c).
const ackTimeoutReason = `SIP ;cause=408 ;text="Request Timeout"`

// AckTimeoutBye builds the BYE that tears down a call whose 200 OK (ok, our
// answer to invite) was never ACKed, as pjsip does after 64*T1. It goes to
// the caller's Contact, with From/To swapped from the caller's view, a new
// CSeq and Via branch, and the Via sent-by the caller addressed the
// honeypot at. It returns nil when invite or ok lacks dialog headers.
func (r *Responder) AckTimeoutBye(invite gosip.Request, ok gosip.Response) gosip.Request {
	from, hasFrom := invite.From()
	to, hasTo := ok.To()
	callID, hasCallID := invite.CallID()
	if !hasFrom || !hasTo || !hasCallID || from.Address == nil || to.Address == nil {
		return nil
	}
	target := from.Address
	if hs := invite.GetHeaders("Contact"); len(hs) > 0 {
		if contact, isContact := hs[0].(*gosip.ContactHeader); isContact && contact.Address != nil {
			if uri, isURI := contact.Address.(gosip.Uri); isURI {
				target = uri
			}
		}
	}

	host, portStr, _ := localTarget(invite)
	portNum, _ := strconv.Atoi(portStr)
	port := gosip.Port(portNum)
	params := gosip.NewParams()
	params.Add("rport", nil)
	params.Add("branch", gosip.String{Str: "z9hG4bKPj" + r.Token()})
	via := gosip.ViaHeader{&gosip.ViaHop{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       "UDP",
		Host:            host,
		Port:            &port,
		Params:          params,
	}}
	maxForwards := gosip.MaxForwards(70)
	localFrom := &gosip.FromHeader{DisplayName: to.DisplayName, Address: to.Address.Clone(), Params: cloneParams(to.Params)}
	remoteTo := &gosip.ToHeader{DisplayName: from.DisplayName, Address: from.Address.Clone(), Params: cloneParams(from.Params)}
	cseq := &gosip.CSeq{SeqNo: uint32(tokenValue(r.Token())%0xffff) + 1, MethodName: gosip.BYE}

	bye := gosip.NewRequest("", gosip.BYE, target.Clone(), invite.SipVersion(), []gosip.Header{
		via,
		&maxForwards,
		localFrom,
		remoteTo,
		callID,
		cseq,
		&gosip.GenericHeader{HeaderName: "Reason", Contents: ackTimeoutReason},
		&gosip.GenericHeader{HeaderName: "User-Agent", Contents: serverAgent},
	}, "", invite.Fields())
	bye.SetBody("", true)
	return bye
}

func cloneParams(p gosip.Params) gosip.Params {
	if p == nil {
		return nil
	}
	return p.Clone()
}
