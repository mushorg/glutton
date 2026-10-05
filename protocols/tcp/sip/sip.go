// Package sip builds the honeypot's SIP replies and extracts the request
// fields recorded in decoded frames. It is shared by the TCP and UDP SIP
// handlers and does no I/O.
package sip

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	gosip "github.com/ghettovoice/gosip/sip"
)

const (
	// Persona: an Asterisk PBX (chan_pjsip) that requires digest auth for every
	// endpoint and rejects whatever credentials are offered.
	serverAgent = "Asterisk PBX 18.20.0"
	realm       = "asterisk"
	allowList   = "OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER"
	supported   = "100rel, timer, replaces, norefersub"
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

// Reply returns the responses to send for req, in order. A nil slice means
// no reply (ACK, or a request the honeypot ignores).
//
// Requests that would create a session or registration (INVITE, REGISTER,
// SUBSCRIBE, MESSAGE, ...) get a 401 digest challenge when unauthenticated and
// 403 Forbidden once they carry credentials, so toll-fraud scanners and
// SIPVicious-style crackers keep sending usernames without ever reaching a call.
func (r *Responder) Reply(req gosip.Request) []gosip.Response {
	switch req.Method() {
	case gosip.ACK:
		return nil
	case gosip.OPTIONS:
		return []gosip.Response{r.response(req, 200, "OK",
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
			&gosip.GenericHeader{HeaderName: "Accept", Contents: "application/sdp"},
			&gosip.GenericHeader{HeaderName: "Supported", Contents: supported},
		)}
	case gosip.INVITE, gosip.REGISTER, gosip.SUBSCRIBE, gosip.NOTIFY, gosip.PUBLISH,
		gosip.MESSAGE, gosip.REFER, gosip.UPDATE, gosip.INFO:
		if Credentials(req) != "" {
			return []gosip.Response{r.response(req, 403, "Forbidden")}
		}
		challenge := `Digest realm="` + realm + `",nonce="` + r.Token() + `",algorithm=MD5,qop="auth"`
		return []gosip.Response{r.response(req, 401, "Unauthorized",
			&gosip.GenericHeader{HeaderName: "WWW-Authenticate", Contents: challenge},
		)}
	case gosip.BYE, gosip.CANCEL, gosip.PRACK:
		return []gosip.Response{r.response(req, 481, "Call/Transaction Does Not Exist")}
	default:
		return []gosip.Response{r.response(req, 501, "Not Implemented",
			&gosip.GenericHeader{HeaderName: "Allow", Contents: allowList},
		)}
	}
}

// response copies the dialog headers from req (RFC 3261 §8.2.6), adds a To
// tag, and appends the persona Server header plus extra.
func (r *Responder) response(req gosip.Request, code gosip.StatusCode, reason string, extra ...gosip.Header) gosip.Response {
	res := gosip.NewResponse("", req.SipVersion(), code, reason, []gosip.Header{}, "", req.Fields())
	gosip.CopyHeaders("Via", req, res)
	gosip.CopyHeaders("From", req, res)
	if to, ok := req.To(); ok {
		to = to.Clone().(*gosip.ToHeader)
		if to.Params == nil {
			to.Params = gosip.NewParams()
		}
		if !to.Params.Has("tag") {
			to.Params.Add("tag", gosip.String{Str: r.Token()})
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
