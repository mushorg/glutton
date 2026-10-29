// Package sip builds the honeypot's SIP replies and extracts the request
// fields recorded in decoded frames. It is shared by the TCP and UDP SIP
// handlers. Its only I/O is framing messages off a reader the TCP handler
// supplies (ReadStreamMessage).
package sip

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

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
// used for To tags and digest nonces, Now the clock stamped into nonces;
// replace them in tests for stable output. A nil Now is time.Now.
type Responder struct {
	Token func() string
	Now   func() time.Time
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

// Variant selects how REGISTER and INVITE are answered. A source returning
// after an idle gap gets the next variant, so each visit shows how the
// scanner reacts to a different outcome. Other methods are answered the same
// way in every variant.
type Variant int

const (
	// Answer accepts REGISTER and answers INVITE with 200 and SDP.
	Answer Variant = iota
	// Progress behaves like Answer but sends 183 Session Progress with the
	// SDP answer (early media) instead of 180 Ringing before the 200. Dial
	// testers that treat early media as a connected call, and ignore a plain
	// 200, may start sending audio or DTMF on it.
	Progress
	// Auth challenges REGISTER and INVITE with 401 until they carry
	// credentials, then behaves like Answer.
	Auth
	// Busy accepts REGISTER and rings INVITE, then rejects it with 486.
	Busy
)

// Variants is the rotation order for returning sources; Answer comes first,
// so a first visit sees the baseline.
var Variants = []Variant{Answer, Progress, Auth, Busy}

func (v Variant) String() string {
	switch v {
	case Answer:
		return "answer"
	case Progress:
		return "progress"
	case Auth:
		return "auth"
	case Busy:
		return "busy"
	}
	return "variant" + strconv.Itoa(int(v))
}

// Escalate returns the variant steps places after v in Variants, skipping
// Answer: the UDP handler moves a source on when it ignores the final
// response it got, without waiting for its next visit. steps <= 0 returns v.
func Escalate(v Variant, steps int) Variant {
	if steps <= 0 || len(Variants) < 2 {
		return v
	}
	// position among the non-Answer variants; Answer sits just before the first
	pos := -1
	for i, cand := range Variants[1:] {
		if cand == v {
			pos = i
		}
	}
	n := len(Variants) - 1
	return Variants[1+((pos+steps)%n+n)%n]
}

// Reply returns the responses to send for req, received from src, in order.
// A nil slice means no reply. The top Via of each response gets received/rport
// filled from src as a real proxy or UA would; src may be nil. local is the
// address req arrived at, used in Contact and SDP when the Request-URI host
// is not an IPv4 address; it may be nil.
func (r *Responder) Reply(req gosip.Request, src, local net.Addr, v Variant) []gosip.Response {
	return annotate(req, src, r.reply(req, local, v)...)
}

// Challenge returns a 401 digest challenge to req, Via annotated for src
// like Reply.
func (r *Responder) Challenge(req gosip.Request, src net.Addr) gosip.Response {
	return annotate(req, src, r.challenge(req))[0]
}

// challenge builds the 401 chan_pjsip sends: res_pjsip_authenticator_digest
// makes the nonce "<unix seconds>/<md5 hex>" and leaves the opaque to
// pjsip_auth_srv_challenge, which draws 16 hex digits and prints the
// parameters in this order with algorithm=md5 (pjsip_MD5_STR) unquoted.
func (r *Responder) challenge(req gosip.Request) gosip.Response {
	challenge := `Digest realm="` + realm + `",nonce="` + r.nonce() + `",opaque="` + r.Token() + `",algorithm=md5,qop="auth"`
	return r.response(req, 401, "Unauthorized", r.Token(),
		&gosip.GenericHeader{HeaderName: "WWW-Authenticate", Contents: challenge},
	)
}

// Answer returns the 100 Trying, the provisional (180 Ringing, or 183
// Session Progress with SDP in the Progress variant) and the 200 OK (with
// SDP) for an INVITE, Via annotated for src like Reply. The UDP handler
// sends the 200 after a ringing delay instead of in the same burst. local is
// as for Reply.
func (r *Responder) Answer(req gosip.Request, src, local net.Addr, v Variant) (trying, ringing, ok gosip.Response) {
	resps := annotate(req, src, r.invite(req, local, v == Progress)...)
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

// nonce returns an Asterisk-style digest nonce: the unix time, a slash and
// the MD5 hex of the time, a random token and the realm (Asterisk hashes
// the source address and its entity ID instead; neither is visible to the
// client, so the shape is what counts).
func (r *Responder) nonce() string {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	sum := md5.Sum([]byte(ts + ":" + r.Token() + ":" + realm))
	return ts + "/" + hex.EncodeToString(sum[:])
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
// REGISTER is accepted with or without credentials (unless sip.register_challenge
// asks for a 401 first, which any credentials then satisfy), and INVITE is answered
// (100 Trying, 180 Ringing, 200 OK with an SDP answer), so scanners that probe
// an extension go on to place the toll-fraud call and reveal the dialed
// number. BYE ends that call with 200. Other session-creating requests
// (SUBSCRIBE, MESSAGE, ...) get a 401 digest challenge when unauthenticated
// and 403 Forbidden once they carry credentials. v changes the REGISTER and
// INVITE outcomes (see Variant).
func (r *Responder) reply(req gosip.Request, local net.Addr, v Variant) []gosip.Response {
	if UnknownExtension(req) {
		// a PBX that tells unknown extensions apart (chan_sip with
		// alwaysauthreject=no) lets enumerators like svwar see which exist
		return []gosip.Response{r.response(req, 404, "Not Found", r.Token())}
	}
	switch req.Method() {
	case gosip.ACK:
		return nil
	case gosip.OPTIONS:
		return []gosip.Response{r.response(req, 200, "OK", r.Token(),
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
			&gosip.GenericHeader{HeaderName: "Accept", Contents: "application/sdp"},
			&gosip.GenericHeader{HeaderName: "Supported", Contents: supported},
			// chan_pjsip's send_options_response adds these to every OPTIONS 200
			&gosip.GenericHeader{HeaderName: "Accept-Encoding", Contents: "identity"},
			&gosip.GenericHeader{HeaderName: "Accept-Language", Contents: "en"},
		)}
	case gosip.REGISTER:
		if (v == Auth || RegisterChallenge()) && Credentials(req) == "" {
			return []gosip.Response{r.challenge(req)}
		}
		return []gosip.Response{r.register(req)}
	case gosip.INVITE:
		if v == Auth && Credentials(req) == "" {
			return []gosip.Response{r.challenge(req)}
		}
		resps := r.invite(req, local, v == Progress)
		if v == Busy {
			// 100 and 180 as usual, then busy instead of the answer
			tag := ""
			if to, ok := resps[1].To(); ok && to.Params != nil {
				if t, ok := to.Params.Get("tag"); ok && t != nil {
					tag = t.String()
				}
			}
			resps[2] = r.response(req, 486, "Busy Here", tag)
		}
		return resps
	case gosip.BYE:
		return []gosip.Response{r.response(req, 200, "OK", r.Token())}
	case gosip.SUBSCRIBE, gosip.NOTIFY, gosip.PUBLISH,
		gosip.MESSAGE, gosip.REFER, gosip.UPDATE, gosip.INFO:
		if Credentials(req) != "" {
			return []gosip.Response{r.response(req, 403, "Forbidden", r.Token())}
		}
		return []gosip.Response{r.challenge(req)}
	case gosip.CANCEL, gosip.PRACK:
		return []gosip.Response{r.response(req, 481, "Call/Transaction Does Not Exist", r.Token())}
	default:
		return []gosip.Response{r.response(req, 501, "Not Implemented", r.Token(),
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
		)}
	}
}

// UnknownExtension reports whether req targets an extension outside
// sip.extensions (see KnownExtension): the To user of a REGISTER, or the
// Request-URI user of an OPTIONS. Other methods and requests without a user
// are never unknown, so INVITE dial strings are answered as before.
func UnknownExtension(req gosip.Request) bool {
	var user gosip.MaybeString
	switch req.Method() {
	case gosip.REGISTER:
		if to, ok := req.To(); ok && to.Address != nil {
			user = to.Address.User()
		}
	case gosip.OPTIONS:
		if uri := req.Recipient(); uri != nil {
			user = uri.User()
		}
	}
	if user == nil || user.String() == "" {
		return false
	}
	return !KnownExtension(user.String())
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

// invite answers the call. 100 Trying carries no To tag; the provisional and
// 200 share one so they belong to the same dialog. With early set the
// provisional is 183 Session Progress carrying the same SDP answer as the
// 200, as Asterisk sends when the dialplan calls Progress().
func (r *Responder) invite(req gosip.Request, local net.Addr, early bool) []gosip.Response {
	host, port, user := localTarget(req, local)
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
	provisional := r.response(req, 180, "Ringing", tag,
		&gosip.GenericHeader{HeaderName: "Contact", Contents: contact},
	)
	if early {
		provisional = r.response(req, 183, "Session Progress", tag,
			&gosip.GenericHeader{HeaderName: "Contact", Contents: contact},
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
			&gosip.GenericHeader{HeaderName: "Supported", Contents: supported},
			&contentType,
		)
		provisional.SetBody(answer, true)
	}
	return []gosip.Response{
		r.response(req, 100, "Trying", ""),
		provisional,
		ok,
	}
}

// localTarget returns the host, port and user of the honeypot as the caller
// addressed it. host is the Request-URI's IPv4 host; when that is a name it
// is local's IPv4 address (where the request arrived), so the SDP points
// media somewhere real, and 0.0.0.0 only when neither is known. port is the
// port the request arrived on, as a UAS advertises its own transport port in
// Contact and Via whatever the Request-URI says; a scanner on a high port
// that is told 5060 sends its ACK elsewhere. Without a local port it is the
// Request-URI port, else 5060. user is the Request-URI user.
func localTarget(req gosip.Request, local net.Addr) (host, port, user string) {
	host, port = "0.0.0.0", "5060"
	if ip := addrIPv4(local); ip != nil {
		host = ip.String()
	}
	localPort := addrPort(local)
	if localPort > 0 {
		port = strconv.Itoa(localPort)
	}
	uri := req.Recipient()
	if uri == nil {
		return host, port, ""
	}
	if ip := net.ParseIP(uri.Host()); ip != nil && ip.To4() != nil {
		host = ip.String()
	}
	if p := uri.Port(); p != nil && localPort == 0 {
		port = strconv.Itoa(int(*p))
	}
	if u := uri.User(); u != nil {
		user = u.String()
	}
	return host, port, user
}

// addrPort returns the port of a, or 0.
func addrPort(a net.Addr) int {
	switch a := a.(type) {
	case *net.UDPAddr:
		if a != nil {
			return a.Port
		}
	case *net.TCPAddr:
		if a != nil {
			return a.Port
		}
	}
	return 0
}

// addrIPv4 returns the IPv4 address of a, or nil.
func addrIPv4(a net.Addr) net.IP {
	var ip net.IP
	switch a := a.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	}
	if ip = ip.To4(); ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
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

// sdpMedia is one m= section of an SDP offer.
type sdpMedia struct {
	kind, proto string
	formats     []string
	dtmf        string // telephone-event payload type of the section, if offered
}

// offeredMedia returns the m= sections of an SDP body in order.
func offeredMedia(offer string) []sdpMedia {
	var media []sdpMedia
	for _, line := range strings.Split(offer, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "m="); ok {
			if fields := strings.Fields(rest); len(fields) >= 3 {
				media = append(media, sdpMedia{kind: fields[0], proto: fields[2], formats: fields[3:]})
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "a=rtpmap:"); ok && len(media) > 0 {
			if pt, enc, ok := strings.Cut(rest, " "); ok && strings.HasPrefix(strings.ToLower(enc), "telephone-event/") {
				media[len(media)-1].dtmf = pt
			}
		}
	}
	return media
}

// audioCodec picks PCMU, else PCMA, from offered payload types, as
// Asterisk's default allow list does; "" when neither is offered.
func audioCodec(formats []string) (codec, name string) {
	for _, f := range formats {
		if f == "0" {
			return "0", "PCMU"
		}
		if f == "8" {
			codec, name = "8", "PCMA"
		}
	}
	return codec, name
}

// sdpAnswer answers the m= sections of offer in order (RFC 3264 section 6):
// the first RTP/AVP audio section offering PCMU or PCMA is accepted on port,
// and every other section is rejected with port 0. An offer without m= lines
// is answered without any, and an empty offer (INVITE without SDP) gets a
// PCMU offer.
func sdpAnswer(offer, host string, port, session int) string {
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d %d IN IP4 %s", session, session+2, host),
		"s=Asterisk",
		"c=IN IP4 " + host,
		"t=0 0",
	}
	media := offeredMedia(offer)
	if len(media) == 0 && strings.TrimSpace(offer) == "" {
		media = []sdpMedia{{kind: "audio", proto: "RTP/AVP", formats: []string{"0"}}}
	}
	accepted := false
	for _, m := range media {
		codec, name := audioCodec(m.formats)
		if accepted || m.kind != "audio" || m.proto != "RTP/AVP" || codec == "" {
			lines = append(lines, "m="+strings.Join(append([]string{m.kind, "0", m.proto}, m.formats...), " "))
			continue
		}
		accepted = true
		formats := codec
		if m.dtmf != "" {
			formats += " " + m.dtmf
		}
		lines = append(lines,
			fmt.Sprintf("m=audio %d RTP/AVP %s", port, formats),
			fmt.Sprintf("a=rtpmap:%s %s/8000", codec, name))
		if m.dtmf != "" {
			lines = append(lines, "a=rtpmap:"+m.dtmf+" telephone-event/8000", "a=fmtp:"+m.dtmf+" 0-16")
		}
		lines = append(lines, "a=ptime:20", "a=maxptime:150", "a=sendrecv")
	}
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
func Credentials(req gosip.Request) string {
	d, _ := digestAuth(req)
	return d.Username
}

// Digest holds the digest-auth fields a request carries in its Authorization
// (or Proxy-Authorization) header. The honeypot issued the nonce in its own
// 401 challenge, so Response is the keyed hash of the password the scanner is
// guessing: with Username, Realm, Nonce, URI, Qop, Nc and CNonce it lets that
// password be recovered offline (e.g. hashcat -m 11400). None of this is a
// secret of ours; Response is the attacker's guess, not a credential we hold.
type Digest struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Algorithm string
	Qop       string
	Nc        string
	CNonce    string
}

// digestAuth parses the first digest Authorization or Proxy-Authorization
// header of req and reports whether one carrying a username or response was
// found. Other schemes (Basic, ...) are ignored.
func digestAuth(req gosip.Request) (Digest, bool) {
	for _, name := range []string{"Authorization", "Proxy-Authorization"} {
		for _, h := range req.GetHeaders(name) {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.Value())), "digest") {
				continue
			}
			a := gosip.AuthFromValue(h.Value())
			d := Digest{
				Username:  a.Username(),
				Realm:     a.Realm(),
				Nonce:     a.Nonce(),
				URI:       a.Uri(),
				Response:  a.Response(),
				Algorithm: a.Algorithm(),
				Qop:       a.Qop(),
				Nc:        a.Nc(),
				CNonce:    a.CNonce(),
			}
			if d.Username != "" || d.Response != "" {
				return d, true
			}
		}
	}
	return Digest{}, false
}

// sipTools maps a lowercased User-Agent substring to the tool family name
// recorded as the fingerprint. SIPVicious ships both as the classic
// "friendly-scanner" and, since the rewrite, as "sipvicious".
var sipTools = []struct{ match, name string }{
	{"friendly-scanner", "sipvicious"},
	{"sipvicious", "sipvicious"},
	{"sipcli", "sipcli"},
	{"sipsak", "sipsak"},
	{"pplsip", "pplsip"},
	{"zxcvfdf", "zxcvfdf"},
	{"vaxsipuseragent", "vaxsipuseragent"},
	{"sundayddr", "sundayddr"},
	{"sipptk", "sipptk"},
	{"sip-scan", "sipscan"},
	{"sipscan", "sipscan"},
	{"sivus", "sivus"},
	{"warvox", "warvox"},
	{"iwar", "iwar"},
	{"smap", "smap"},
	{"sipslaughter", "sipslaughter"},
	{"architect-tcp", "architect-tcp"},
}

// sipToolsExact maps a whole lowercased User-Agent to a tool family, for
// names too generic to match as a substring.
var sipToolsExact = map[string]string{
	"voip": "voip",
}

// Tool classifies the SIP tool behind req from its User-Agent and, failing
// that, a header or body habit, returning "" when nothing matches. The name
// is the tool family (SIPVicious, sipcli, sipsak, pplsip, VaxSIPUserAgent,
// SipSlaughter, ...) or, for a fleet that forges its User-Agent, its tell
// (sqli-from, zoiper-fleet, sip-scan-call, options-ping, sippts,
// pjsip-python). User-Agent matches, in any of the request's User-Agent
// headers, win. It is a triage hint, not proof: a scanner can forge any
// header.
func Tool(req gosip.Request) string {
	uas := req.GetHeaders("User-Agent")
	for _, h := range uas {
		ua := strings.ToLower(strings.TrimSpace(h.Value()))
		if name, ok := sipToolsExact[ua]; ok {
			return name
		}
		for _, t := range sipTools {
			if strings.Contains(ua, t.match) {
				return t.name
			}
		}
	}
	ua := ""
	if len(uas) > 0 {
		ua = strings.ToLower(uas[0].Value())
	}
	// SIPVicious defaults the From and To domain to 1.1.1.1 unless its caller
	// sets one, and its svhelper builds the Via branch as z9hG4bK-<decimal>
	// (with rport) and the From tag as the hex of <data>\x01<decimal>; these
	// tells survive a changed User-Agent.
	if fromToHost(req) == "1.1.1.1" || sipviciousTag(fromTag(req)) ||
		(sipviciousBranch.MatchString(viaBranch(req)) && viaHasParam(req, "rport")) {
		return "sipvicious"
	}
	// SipSlaughter reuses one mrb-<hex>-<hex> token in its Call-ID, Via
	// branch and From tag, whatever User-Agent it sends
	if sipslaughterCallID.MatchString(callIDValue(req)) {
		return "sipslaughter"
	}
	// a dial fleet puts SQL injection (`')or('x'='x`) in the From, Contact
	// and P-Preferred-Identity users, aimed at PBX or billing lookups
	for _, name := range []string{"From", "Contact", "P-Preferred-Identity"} {
		for _, h := range req.GetHeaders(name) {
			v := strings.ToLower(h.Value())
			if strings.Contains(v, "'or(") || strings.Contains(v, "')or('") {
				return "sqli-from"
			}
		}
	}
	// the same fleet forges a new phone User-Agent per call, but its SDP
	// still names the Zoiper stack it is built on
	if sdpSessionName(string(req.Body())) == "zoiper" && !strings.Contains(ua, "zoiper") {
		return "zoiper-fleet"
	}
	// a dial fleet that rotates its User-Agent (2N, Gequdio, OpenSIPS) but
	// always names its SDP session this, with media at 0.0.0.0
	if sdpSessionName(string(req.Body())) == "sip scan call" {
		return "sip-scan-call"
	}
	// the minimal liveness probe "OPTIONS sip:1@1" sent from many networks:
	// no User-Agent, Call-ID 1 and a one-character Via branch
	if req.Method() == gosip.OPTIONS && len(uas) == 0 && callIDValue(req) == "1" && len(viaBranch(req)) == 1 {
		return "options-ping"
	}
	// sippts (whose default User-Agent is pplsip) with the User-Agent left
	// out: numeric "N-N-N" Call-ID and a digits-only Via branch
	if len(uas) == 0 && sipptsCallID.MatchString(callIDValue(req)) && sipptsBranch.MatchString(viaBranch(req)) {
		return "sippts"
	}
	// a script on the pjsip Python bindings: pjsip's z9hG4bKPj branch with
	// no User-Agent (real pjsip phones and Asterisk send one)
	if len(uas) == 0 && strings.HasPrefix(viaBranch(req), "z9hG4bKPj") {
		return "pjsip-python"
	}
	return ""
}

var (
	sipptsCallID       = regexp.MustCompile(`^\d+-\d+-\d+$`)
	sipptsBranch       = regexp.MustCompile(`^z9hG4bK\d+$`)
	sipviciousBranch   = regexp.MustCompile(`^z9hG4bK-\d+$`)
	sipslaughterCallID = regexp.MustCompile(`^mrb-[0-9a-f]+-[0-9a-f]+@pbx$`)
)

// sipviciousTag reports whether tag is SIPVicious' createTag output: the hex
// of <data>\x01<random decimal>.
func sipviciousTag(tag string) bool {
	raw, err := hex.DecodeString(tag)
	if err != nil {
		return false
	}
	data, rnd, ok := bytes.Cut(raw, []byte{1})
	if !ok || len(data) == 0 || len(rnd) == 0 {
		return false
	}
	for _, c := range rnd {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// fromTag returns the tag parameter of the From header, or "".
func fromTag(req gosip.Request) string {
	from, ok := req.From()
	if !ok || from.Params == nil {
		return ""
	}
	if tag, ok := from.Params.Get("tag"); ok && tag != nil {
		return tag.String()
	}
	return ""
}

// viaHasParam reports whether the top Via hop carries the parameter name.
func viaHasParam(req gosip.Request, name string) bool {
	hop, ok := req.ViaHop()
	return ok && hop.Params != nil && hop.Params.Has(name)
}

// sdpSessionName returns the lowercased s= line of an SDP body, or "".
func sdpSessionName(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "s="); ok {
			return strings.ToLower(strings.TrimSpace(name))
		}
	}
	return ""
}

func callIDValue(req gosip.Request) string {
	if callID, ok := req.CallID(); ok {
		return callID.Value()
	}
	return ""
}

// viaBranch returns the branch parameter of the top Via hop, or "".
func viaBranch(req gosip.Request) string {
	hop, ok := req.ViaHop()
	if !ok || hop.Params == nil {
		return ""
	}
	if branch, ok := hop.Params.Get("branch"); ok && branch != nil {
		return branch.String()
	}
	return ""
}

// fromToHost returns the URI host shared by the From and To headers, or "".
func fromToHost(req gosip.Request) string {
	from, okFrom := req.From()
	to, okTo := req.To()
	if !okFrom || !okTo || from.Address == nil || to.Address == nil {
		return ""
	}
	if h := from.Address.Host(); h != "" && h == to.Address.Host() {
		return h
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
	// CalledNumber is the dialed number of a request (see CalledNumber).
	CalledNumber string
	// Tool is the fingerprinted client tool of a request (see Tool).
	Tool string
	// Digest is the digest-auth credentials a request carried (see Digest).
	Digest Digest
}

// CalledNumber returns the number req dials: the Refer-To user of a REFER,
// else the Request-URI user, else the To user, with URI parameters and
// visual separators ("-.() ") removed and a leading "+" kept. It is "" for REGISTER (whose To is the binding being
// registered, not a call target) and for users that are not made of digits,
// "*" and "#" (names like "asterisk" or "admin").
func CalledNumber(req gosip.Request) string {
	switch req.Method() {
	case gosip.REGISTER:
		return ""
	case gosip.REFER:
		// a transfer dials the Refer-To target, not the party it is sent to
		if hs := req.GetHeaders("Refer-To"); len(hs) > 0 {
			return normalizeNumber(uriUser(hs[0].Value()))
		}
	}
	user := ""
	if uri := req.Recipient(); uri != nil && uri.User() != nil {
		user = uri.User().String()
	}
	if user == "" {
		if to, ok := req.To(); ok && to.Address != nil && to.Address.User() != nil {
			user = to.Address.User().String()
		}
	}
	return normalizeNumber(user)
}

// uriUser returns the user part of a name-addr or bare URI header value
// ("<sip:0044123@host;user=phone>?Replaces=..."), or "".
func uriUser(value string) string {
	if _, inner, ok := strings.Cut(value, "<"); ok {
		value, _, _ = strings.Cut(inner, ">")
	}
	_, rest, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return ""
	}
	user, _, hasHost := strings.Cut(rest, "@")
	if !hasHost {
		return ""
	}
	return user
}

// normalizeNumber reduces a URI user part to a dialed number, or "".
func normalizeNumber(user string) string {
	user, _, _ = strings.Cut(user, ";")
	var b strings.Builder
	for i, c := range user {
		switch {
		case c >= '0' && c <= '9', c == '*', c == '#':
			b.WriteRune(c)
		case c == '+' && i == 0:
			b.WriteRune(c)
		case strings.ContainsRune("-.() ", c):
		default:
			return ""
		}
	}
	if n := b.String(); strings.TrimPrefix(n, "+") != "" {
		return n
	}
	return ""
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
		info.Digest, _ = digestAuth(m)
		info.Username = info.Digest.Username
		info.CalledNumber = CalledNumber(m)
		info.Tool = Tool(m)
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
			// a client that sends the header twice (SipSlaughter adds
			// "Softphone/2.1.0") keeps both, in order
			values := make([]string, 0, len(hs))
			for _, h := range hs {
				values = append(values, h.Value())
			}
			info.UserAgent = strings.Join(values, ", ")
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

// startMethods are the request methods (and the response prefix) MayStart
// recognizes; they match the Allow list.
var startMethods = []string{"SIP/", "REGISTER", "INVITE", "OPTIONS", "ACK", "BYE", "CANCEL", "SUBSCRIBE", "NOTIFY", "MESSAGE", "INFO", "PRACK", "REFER", "PUBLISH", "UPDATE"}

// MayStart reports whether snip (the first bytes of a stream) could begin a
// SIP request line or status line.
func MayStart(snip []byte) bool {
	if len(snip) == 0 {
		return false
	}
	for _, m := range startMethods {
		n := min(len(snip), len(m))
		if bytes.Equal(snip[:n], []byte(m)[:n]) {
			return true
		}
	}
	return false
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
// answer to invite) was never ACKed, as pjsip does after 64*T1 (see
// InDialogRequest for its addressing). It returns nil when invite or ok
// lacks dialog headers.
func (r *Responder) AckTimeoutBye(invite gosip.Request, ok gosip.Response, local net.Addr, transport string) gosip.Request {
	return r.InDialogRequest(gosip.BYE, invite, ok, local, transport, 0, "",
		&gosip.GenericHeader{HeaderName: "Reason", Contents: ackTimeoutReason},
	)
}

// InDialogRequest builds a request the honeypot sends inside the call that
// ok (our answer to invite) set up. It goes to the caller's Contact, with
// From/To swapped from the caller's view, a new Via branch, and the Via
// sent-by the caller addressed the honeypot at (or local, as for Reply) over
// transport ("UDP", "TCP" or "TLS"). seq is its CSeq number, 0 for a random
// one. extra headers come before User-Agent; a non-empty body is sent as is
// (extra must then carry its Content-Type). It returns nil when invite or
// ok lacks dialog headers. Only the Request-URI names the Contact: the UDP
// handler sends it to the packet source, never to an address the caller
// supplied.
func (r *Responder) InDialogRequest(method gosip.RequestMethod, invite gosip.Request, ok gosip.Response, local net.Addr, transport string, seq uint32, body string, extra ...gosip.Header) gosip.Request {
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

	host, portStr, _ := localTarget(invite, local)
	portNum, _ := strconv.Atoi(portStr)
	port := gosip.Port(portNum)
	params := gosip.NewParams()
	params.Add("rport", nil)
	params.Add("branch", gosip.String{Str: "z9hG4bKPj" + r.Token()})
	via := gosip.ViaHeader{&gosip.ViaHop{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       transport,
		Host:            host,
		Port:            &port,
		Params:          params,
	}}
	maxForwards := gosip.MaxForwards(70)
	localFrom := &gosip.FromHeader{DisplayName: to.DisplayName, Address: to.Address.Clone(), Params: cloneParams(to.Params)}
	remoteTo := &gosip.ToHeader{DisplayName: from.DisplayName, Address: from.Address.Clone(), Params: cloneParams(from.Params)}
	if seq == 0 {
		seq = uint32(tokenValue(r.Token())%0xffff) + 1
	}
	cseq := &gosip.CSeq{SeqNo: seq, MethodName: method}

	headers := []gosip.Header{via, &maxForwards, localFrom, remoteTo, callID, cseq}
	headers = append(headers, extra...)
	headers = append(headers, &gosip.GenericHeader{HeaderName: "User-Agent", Contents: serverAgent})
	req := gosip.NewRequest("", method, target.Clone(), invite.SipVersion(), headers, "", invite.Fields())
	req.SetBody(body, true)
	return req
}

// referExpires is the Subscription-State expiry of the implicit refer
// subscription while the transfer is pending.
const referExpires = 60

// ReferNotify builds the NOTIFY that reports a REFER's progress inside the
// call ok answered (RFC 3515 §2.4.5): a message/sipfrag body with the
// transfer's status line, "100 Trying" while it is pending and "200 OK"
// once it is done, which also terminates the subscription. Asterisk
// (res_pjsip_refer) sends these after accepting a blind transfer. seq is the
// CSeq number, as for InDialogRequest.
func (r *Responder) ReferNotify(invite gosip.Request, ok gosip.Response, local net.Addr, transport string, seq uint32, done bool) gosip.Request {
	state, frag := "active;expires="+strconv.Itoa(referExpires), "SIP/2.0 100 Trying\r\n"
	if done {
		state, frag = "terminated;reason=noresource", "SIP/2.0 200 OK\r\n"
	}
	contentType := gosip.ContentType("message/sipfrag;version=2.0")
	return r.InDialogRequest(gosip.NOTIFY, invite, ok, local, transport, seq, frag,
		&gosip.GenericHeader{HeaderName: "Event", Contents: "refer"},
		&gosip.GenericHeader{HeaderName: "Subscription-State", Contents: state},
		&contentType,
	)
}

// ReInviteOK answers a re-INVITE inside the call that ok (our 200 to the
// first INVITE) set up: 200 OK with the same Contact and SDP answer, so the
// session stays as it was. Via is annotated for src like Reply.
func (r *Responder) ReInviteOK(req gosip.Request, src net.Addr, ok gosip.Response) gosip.Response {
	var extra []gosip.Header
	for _, name := range []string{"Contact", "Allow", "Supported", "Content-Type"} {
		for _, h := range ok.GetHeaders(name) {
			extra = append(extra, h.Clone())
		}
	}
	tag := ""
	if to, hasTo := ok.To(); hasTo && to.Params != nil {
		if t, hasTag := to.Params.Get("tag"); hasTag && t != nil {
			tag = t.String()
		}
	}
	res := r.response(req, 200, "OK", tag, extra...)
	res.SetBody(ok.Body(), true)
	return annotate(req, src, res)[0]
}

func cloneParams(p gosip.Params) gosip.Params {
	if p == nil {
		return nil
	}
	return p.Clone()
}
