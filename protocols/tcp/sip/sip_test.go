package sip

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghettovoice/gosip/log"
	gosip "github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/stretchr/testify/require"
)

// read frame 1 of Ochi event 748a8b05-6a95-4592-94b5-15cb4ea65164 (pplsip toll-fraud INVITE)
var pplsipInvite = []byte("INVITE sip:14500972598112101@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\nMax-Forwards: 70\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 1 INVITE\r\nContact: <sip:14500163172166221:5060@212.129.10.158:65145>\r\nUser-Agent: pplsip\r\nContent-Type: application/sdp\r\nContent-Length: 211\r\n\r\nv=0\r\no=14500163172166221:5060 16264 18299 IN IP4 0.0.0.0\r\ns=pplsip\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 25282 RTP/AVP 100 6 0 8 3 18 5 101\r\na=rtpmap:0 pcmu/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\n")

func parseRequest(t *testing.T, data []byte) gosip.Request {
	t.Helper()
	msg, err := parser.NewPacketParser(log.NewDefaultLogrusLogger()).ParseMessage(data)
	require.NoError(t, err)
	req, ok := msg.(gosip.Request)
	require.True(t, ok)
	return req
}

func withAuth(data []byte, header string) []byte {
	return []byte(strings.Replace(string(data), "User-Agent: pplsip\r\n", "User-Agent: pplsip\r\n"+header+"\r\n", 1))
}

// testNow is the clock test responders stamp into digest nonces.
func testNow() time.Time { return time.Unix(1761350400, 0) }

func testResponder() *Responder {
	return &Responder{Token: func() string { return "0123456789abcdef" }, Now: testNow}
}

func TestReplyInviteAnswered(t *testing.T) {
	resps := testResponder().Reply(parseRequest(t, pplsipInvite), nil, nil, Answer)
	require.Len(t, resps, 3)
	require.Equal(t, gosip.StatusCode(100), resps[0].StatusCode())
	to, _ := resps[0].To()
	require.False(t, to.Params.Has("tag"), "100 Trying carries no To tag")
	require.Equal(t, gosip.StatusCode(180), resps[1].StatusCode())

	require.Equal(t, "SIP/2.0 200 OK\r\n"+
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n"+
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n"+
		"To: <sip:14500972598112101@1.2.3.4>;tag=0123456789abcdef\r\n"+
		"Call-ID: 1492163839-465544234-336545636\r\n"+
		"CSeq: 1 INVITE\r\n"+
		"Server: Asterisk PBX 18.20.0\r\n"+
		"Contact: <sip:14500972598112101@1.2.3.4:5060>\r\n"+
		"Allow: "+allowList+"\r\n"+
		"Supported: "+supported+"\r\n"+
		"Content-Type: application/sdp\r\n"+
		"Content-Length: 217\r\n\r\n"+
		"v=0\r\n"+
		"o=- 88743 88745 IN IP4 1.2.3.4\r\n"+
		"s=Asterisk\r\n"+
		"c=IN IP4 1.2.3.4\r\n"+
		"t=0 0\r\n"+
		"m=audio 17486 RTP/AVP 0 101\r\n"+
		"a=rtpmap:0 PCMU/8000\r\n"+
		"a=rtpmap:101 telephone-event/8000\r\n"+
		"a=fmtp:101 0-16\r\n"+
		"a=ptime:20\r\n"+
		"a=maxptime:150\r\n"+
		"a=sendrecv\r\n", resps[2].String())
	// 180 and 200 belong to the same dialog
	ringTo, _ := resps[1].To()
	okTo, _ := resps[2].To()
	require.Equal(t, mustParam(t, ringTo.Params, "tag"), mustParam(t, okTo.Params, "tag"))
}

func TestAnswerMatchesReply(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	req := parseRequest(t, pplsipInvite)
	trying, ringing, ok := testResponder().Answer(req, src, nil, Answer)
	resps := testResponder().Reply(req, src, nil, Answer)
	require.Equal(t, []string{resps[0].String(), resps[1].String(), resps[2].String()},
		[]string{trying.String(), ringing.String(), ok.String()})
	require.Contains(t, ok.String(), ";received=51.75.106.116\r\n")
}

func TestFinal(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	req := parseRequest(t, pplsipInvite)
	want := func(status, tag string) string {
		return "SIP/2.0 " + status + "\r\n" +
			"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159;received=51.75.106.116\r\n" +
			"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
			"To: <sip:14500972598112101@1.2.3.4>;tag=" + tag + "\r\n" +
			"Call-ID: 1492163839-465544234-336545636\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Server: Asterisk PBX 18.20.0\r\n" +
			"Content-Length: 0\r\n\r\n"
	}
	// an empty tag draws a new one
	require.Equal(t, want("404 Not Found", "0123456789abcdef"), testResponder().Final(req, src, 404, "Not Found", "").String())
	require.Equal(t, want("487 Request Terminated", "ringtag"), testResponder().Final(req, src, 487, "Request Terminated", "ringtag").String())
}

func TestSDPAnswerCodecs(t *testing.T) {
	answer := sdpAnswer("v=0\r\nm=audio 4000 RTP/AVP 18 8\r\n", "1.2.3.4", 10000, 1)
	require.Contains(t, answer, "m=audio 10000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	require.NotContains(t, answer, "telephone-event")

	// late offer (no SDP) gets PCMU
	answer = sdpAnswer("", "0.0.0.0", 10002, 1)
	require.Contains(t, answer, "m=audio 10002 RTP/AVP 0\r\n")
	require.Contains(t, answer, "c=IN IP4 0.0.0.0\r\n")
}

func TestReplyRegisterAccepted(t *testing.T) {
	register := func(extra string) gosip.Response {
		req := parseRequest(t, []byte("REGISTER sip:1.2.3.4:5060 SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 185.243.5.243:49618;branch=z9hG4bK-1;rport\r\n"+
			"From: <sip:100@1.2.3.4>;tag=a\r\n"+
			"To: <sip:100@1.2.3.4>\r\n"+
			"Call-ID: 1\r\n"+
			"CSeq: 1 REGISTER\r\n"+
			"Contact: <sip:100@185.243.5.243:49618>"+extra+
			"Content-Length: 0\r\n\r\n"))
		resps := testResponder().Reply(req, nil, nil, Answer)
		require.Len(t, resps, 1)
		require.Equal(t, gosip.StatusCode(200), resps[0].StatusCode())
		return resps[0]
	}

	out := register("\r\nExpires: 60\r\n").String()
	require.Contains(t, out, "Contact: <sip:100@185.243.5.243:49618>;expires=60\r\nExpires: 60\r\n")

	out = register(";expires=120\r\n").String()
	require.Contains(t, out, "Contact: <sip:100@185.243.5.243:49618>;expires=120\r\nExpires: 120\r\n")

	// no expiry requested, or more than allowed: the default
	require.Contains(t, register("\r\n").String(), "Expires: 3600\r\n")
	require.Contains(t, register("\r\nExpires: 999999\r\n").String(), "Expires: 3600\r\n")

	// unregister drops the binding
	out = register("\r\nExpires: 0\r\n").String()
	require.NotContains(t, out, "Contact:")
	require.Contains(t, out, "Expires: 0\r\n")
}

func TestReplyAuthenticatedRejected(t *testing.T) {
	message := []byte(strings.ReplaceAll(string(pplsipInvite), "INVITE", "MESSAGE"))
	for _, header := range []string{
		`Authorization: Digest username="1000",realm="asterisk",nonce="0123456789abcdef",uri="sip:14500972598112101@1.2.3.4",response="d41d8cd98f00b204e9800998ecf8427e",algorithm=MD5`,
		`Proxy-Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`,
	} {
		req := parseRequest(t, withAuth(message, header))
		require.Equal(t, "1000", Credentials(req))
		resps := testResponder().Reply(req, nil, nil, Answer)
		require.Len(t, resps, 1)
		require.Equal(t, gosip.StatusCode(403), resps[0].StatusCode())
		require.Equal(t, "Forbidden", resps[0].Reason())
		require.Empty(t, resps[0].GetHeaders("WWW-Authenticate"))
	}
}

func TestReplyRegisterWithCredentialsAccepted(t *testing.T) {
	register := []byte(strings.ReplaceAll(string(pplsipInvite), "INVITE", "REGISTER"))
	req := parseRequest(t, withAuth(register, `Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`))
	resps := testResponder().Reply(req, nil, nil, Answer)
	require.Len(t, resps, 1)
	require.Equal(t, gosip.StatusCode(200), resps[0].StatusCode())
}

func TestReplyOptions(t *testing.T) {
	req := parseRequest(t, []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport\r\n"+
		"From: \"sipvicious\"<sip:100@1.1.1.1>;tag=abc\r\n"+
		"To: \"sipvicious\"<sip:100@1.1.1.1>\r\n"+
		"Call-ID: 12345\r\n"+
		"CSeq: 1 OPTIONS\r\n"+
		"Content-Length: 0\r\n\r\n"))
	resps := testResponder().Reply(req, nil, nil, Answer)
	require.Len(t, resps, 1)
	out := resps[0].String()
	require.True(t, strings.HasPrefix(out, "SIP/2.0 200 OK\r\n"), out)
	require.Contains(t, out, "To: \"sipvicious\" <sip:100@1.1.1.1>;tag=0123456789abcdef\r\n")
	require.Contains(t, out, "Allow: OPTIONS, REGISTER")
	require.Contains(t, out, "Server: Asterisk PBX 18.20.0\r\n")
	require.NotContains(t, strings.ToLower(out), "glutton")
}

func TestReplyKeepsExistingToTag(t *testing.T) {
	req := parseRequest(t, []byte(strings.Replace(string(pplsipInvite),
		"To: <sip:14500972598112101@1.2.3.4>\r\n", "To: <sip:14500972598112101@1.2.3.4>;tag=peer\r\n", 1)))
	out := testResponder().Reply(req, nil, nil, Answer)[0].String()
	require.Contains(t, out, "To: <sip:14500972598112101@1.2.3.4>;tag=peer\r\n")
	// the request itself is not mutated
	to, _ := req.To()
	require.Equal(t, "peer", mustParam(t, to.Params, "tag"))
}

func mustParam(t *testing.T, p gosip.Params, key string) string {
	t.Helper()
	v, ok := p.Get(key)
	require.True(t, ok)
	return v.String()
}

func TestReplyMethods(t *testing.T) {
	cases := map[string]int{
		"ACK":       0,
		"BYE":       200,
		"CANCEL":    481,
		"REGISTER":  200,
		"SUBSCRIBE": 401,
		"MESSAGE":   401,
	}
	for method, want := range cases {
		data := strings.ReplaceAll(string(pplsipInvite), "INVITE", method)
		resps := testResponder().Reply(parseRequest(t, []byte(data)), nil, nil, Answer)
		if want == 0 {
			require.Empty(t, resps, method)
			continue
		}
		require.Len(t, resps, 1, method)
		require.Equal(t, gosip.StatusCode(want), resps[0].StatusCode(), method)
	}
}

func TestDescribe(t *testing.T) {
	info := Describe(parseRequest(t, pplsipInvite))
	require.Equal(t, Info{
		Method:       "INVITE",
		URI:          "sip:14500972598112101@1.2.3.4",
		From:         "sip:14500163172166221:5060@1.2.3.4",
		To:           "sip:14500972598112101@1.2.3.4",
		CallID:       "1492163839-465544234-336545636",
		UserAgent:    "pplsip",
		CalledNumber: "14500972598112101",
		Tool:         "pplsip",
	}, info)

	resp := testResponder().Reply(parseRequest(t, pplsipInvite), nil, nil, Answer)[2]
	info = Describe(resp)
	require.Equal(t, 200, info.Status)
	require.Equal(t, "Asterisk PBX 18.20.0", info.UserAgent)
	require.Empty(t, info.Method)
}

func TestCredentialsIgnoresNonDigest(t *testing.T) {
	req := parseRequest(t, withAuth(pplsipInvite, `Authorization: Basic dXNlcjpwYXNz`))
	require.Empty(t, Credentials(req))
}

func TestDigestAuth(t *testing.T) {
	// a REGISTER answering the honeypot's own challenge: its nonce is ours, so
	// response + these fields crack the guessed password offline.
	req := parseRequest(t, withAuth(pplsipInvite, `Authorization: Digest username="1000",realm="asterisk",nonce="abc123",uri="sip:1.2.3.4",response="deadbeef",algorithm=MD5,qop=auth,nc=00000001,cnonce="xyz"`))
	info := Describe(req)
	require.Equal(t, Digest{
		Username:  "1000",
		Realm:     "asterisk",
		Nonce:     "abc123",
		URI:       "sip:1.2.3.4",
		Response:  "deadbeef",
		Algorithm: "MD5",
		Qop:       "auth",
		Nc:        "00000001",
		CNonce:    "xyz",
	}, info.Digest)
	require.Equal(t, "1000", info.Username)
}

func TestDigestAuthAbsent(t *testing.T) {
	require.Equal(t, Digest{}, Describe(parseRequest(t, pplsipInvite)).Digest)
}

func TestTool(t *testing.T) {
	// a toll-fraud INVITE whose only varying part is the User-Agent
	withUA := func(ua string) gosip.Request {
		data := strings.Replace(string(pplsipInvite), "User-Agent: pplsip\r\n", "User-Agent: "+ua+"\r\n", 1)
		return parseRequest(t, []byte(data))
	}
	cases := []struct{ ua, tool string }{
		{"friendly-scanner", "sipvicious"},
		{"sipvicious", "sipvicious"},
		{"sipcli/v1.8", "sipcli"},
		{"sipsak 0.9.7", "sipsak"},
		{"pplsip", "pplsip"},
		{"VaxSIPUserAgent/3.1", "vaxsipuseragent"},
		{"sundayddr", "sundayddr"},
		{"zxcvfdf11", "zxcvfdf"},
		{"Asterisk PBX 18.20.0", ""},
		{"Zoiper rev.12345", ""},
	}
	for _, c := range cases {
		require.Equal(t, c.tool, Tool(withUA(c.ua)), "User-Agent %q", c.ua)
	}
}

func TestToolFromToHost(t *testing.T) {
	// SIPVicious with a changed User-Agent still defaults From/To to 1.1.1.1
	data := "OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK1\r\n" +
		"From: \"1000\"<sip:1000@1.1.1.1>;tag=a\r\n" +
		"To: \"1000\"<sip:1000@1.1.1.1>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"User-Agent: PBX\r\n" +
		"Content-Length: 0\r\n\r\n"
	require.Equal(t, "sipvicious", Tool(parseRequest(t, []byte(data))))
}

func TestReplyViaReceivedAndRport(t *testing.T) {
	request := func(via string) gosip.Request {
		return parseRequest(t, []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n"+
			via+
			"From: <sip:100@1.2.3.4>;tag=a\r\n"+
			"To: <sip:100@1.2.3.4>\r\n"+
			"Call-ID: 1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Content-Length: 0\r\n\r\n"))
	}
	udp := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	cases := []struct {
		name string
		via  string
		src  net.Addr
		want string
	}{
		{"sent-by matches source", "Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1\r\n", udp,
			"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1\r\n"},
		{"sent-by differs", "Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1\r\n", udp,
			"Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1;received=203.0.113.10\r\n"},
		{"sent-by is a name", "Via: SIP/2.0/UDP pbx.example:5079;branch=z9hG4bK-1\r\n", udp,
			"Via: SIP/2.0/UDP pbx.example:5079;branch=z9hG4bK-1;received=203.0.113.10\r\n"},
		{"rport requested", "Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport\r\n", udp,
			"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport=5079;received=203.0.113.10\r\n"},
		{"rport behind NAT", "Via: SIP/2.0/UDP 10.0.0.5:5060;rport;branch=z9hG4bK-1\r\n", udp,
			"Via: SIP/2.0/UDP 10.0.0.5:5060;rport=5079;branch=z9hG4bK-1;received=203.0.113.10\r\n"},
		{"tcp source", "Via: SIP/2.0/TCP 0.0.0.0:5079;branch=z9hG4bK-1\r\n", &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 40000},
			"Via: SIP/2.0/TCP 0.0.0.0:5079;branch=z9hG4bK-1;received=203.0.113.10\r\n"},
		{"no source", "Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1;rport\r\n", nil,
			"Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1;rport\r\n"},
		{"only the top hop", "Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1\r\nVia: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-0\r\n", udp,
			"Via: SIP/2.0/UDP 0.0.0.0:5079;branch=z9hG4bK-1;received=203.0.113.10\r\nVia: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-0\r\n"},
	}
	for _, c := range cases {
		req := request(c.via)
		out := testResponder().Reply(req, c.src, nil, Answer)[0].String()
		require.Contains(t, out, "\r\n"+c.want+"From:", c.name)
		// the request is not mutated
		require.NotContains(t, req.String(), "received=", c.name)
	}
}

func TestLooksLikeSIP(t *testing.T) {
	for _, data := range [][]byte{
		pplsipInvite,
		[]byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4\r\n\r\n"),
		[]byte("REGISTER sips:example.com SIP/2.0\r\n\r\n"),
		[]byte("INVITE tel:+15551234 SIP/2.0\r\n"),
		[]byte("SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n\r\n"),
		[]byte("REGISTER sip:201@1.2.3.4 SIP/2.0\nTo: 201 <sip:201@1.2.3.4>\n"), // bare LF
		[]byte("SIP/2.0 200 OK\nCSeq: 1 OPTIONS\n"),
	} {
		require.True(t, LooksLikeSIP(data), "%q", data)
	}
	for _, data := range [][]byte{
		nil,
		[]byte("INVITE sip:100@1.2.3.4 SIP/2.0"), // no line end
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),          // HTTP
		[]byte("GET sip:100@1.2.3.4 HTTP/1.1\r\n"),           // wrong version
		[]byte("invite sip:100@1.2.3.4 SIP/2.0\r\n"),         // lowercase method
		[]byte("INVITE http://1.2.3.4/ SIP/2.0\r\n"),         // wrong scheme
		[]byte("SIP/2.0 OK\r\n"),                             // no status code
		[]byte("SIP/2.0 999 Nope\r\n"),                       // status out of range
		append([]byte("INVITE sip:"), make([]byte, 1024)...), // line end beyond scan window
		{0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02},
	} {
		require.False(t, LooksLikeSIP(data), "%q", data)
	}
}

func TestNormalizeHeaders(t *testing.T) {
	for _, c := range []struct {
		name      string
		in        string
		terminate bool
		want      string
	}{
		{"empty", "", true, ""},
		{"crlf unchanged", "OPTIONS sip:1.2.3.4 SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n", true, "OPTIONS sip:1.2.3.4 SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n"},
		{"crlf with body unchanged", "INVITE sip:1 SIP/2.0\r\nContent-Length: 6\r\n\r\nv=0\r\n\n", true, "INVITE sip:1 SIP/2.0\r\nContent-Length: 6\r\n\r\nv=0\r\n\n"},
		{"lf only, terminated", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REGISTER\n\n", true, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"lf only, no empty line", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REGISTER\n", true, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"no final line end", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REGISTER", true, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"crlf, no empty line", "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n", true, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"mixed line ends", "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\n\r\n", true, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"lf with sdp body kept", "INVITE sip:1 SIP/2.0\nContent-Type: application/sdp\nContent-Length: 15\n\nv=0\nc=IN IP4 0\n", true, "INVITE sip:1 SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: 15\r\n\r\nv=0\nc=IN IP4 0\n"},
		{"stream: lf converted", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REGISTER\n\n", false, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"},
		{"stream: end not guessed", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REG", false, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REG"},
		{"stream: no empty line", "REGISTER sip:1 SIP/2.0\nCSeq: 1 REGISTER\n", false, "REGISTER sip:1 SIP/2.0\r\nCSeq: 1 REGISTER\r\n"},
	} {
		in := []byte(c.in)
		orig := string(in)
		require.Equal(t, c.want, string(NormalizeHeaders(in, c.terminate)), c.name)
		require.Equal(t, orig, string(in), "%s: input mutated", c.name)
	}
	// the normalized LF message parses
	parseRequest(t, NormalizeHeaders([]byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\nVia: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK1\nFrom: <sip:a@1.2.3.4>;tag=1\nTo: <sip:100@1.2.3.4>\nCall-ID: x\nCSeq: 1 OPTIONS\n"), true))
}

func TestAckTimeoutBye(t *testing.T) {
	r := testResponder()
	invite := parseRequest(t, pplsipInvite)
	ok := r.Reply(invite, nil, nil, Answer)[2]

	bye := r.AckTimeoutBye(invite, ok, nil, "UDP")
	require.NotNil(t, bye)
	// goes to the caller's Contact; From/To swap sides and keep both tags;
	// Reason matches pjsip's ACK-timeout BYE
	require.Equal(t, "BYE sip:14500163172166221:5060@212.129.10.158:65145 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 1.2.3.4:5060;rport;branch=z9hG4bKPj0123456789abcdef\r\n"+
		"Max-Forwards: 70\r\n"+
		"From: <sip:14500972598112101@1.2.3.4>;tag=0123456789abcdef\r\n"+
		"To: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n"+
		"Call-ID: 1492163839-465544234-336545636\r\n"+
		"CSeq: 18059 BYE\r\n"+
		`Reason: SIP ;cause=408 ;text="Request Timeout"`+"\r\n"+
		"User-Agent: Asterisk PBX 18.20.0\r\n"+
		"Content-Length: 0\r\n\r\n", bye.String())

	// building the BYE must not touch the stored INVITE/200 OK
	to, _ := ok.To()
	require.Equal(t, "0123456789abcdef", mustParam(t, to.Params, "tag"))
	from, _ := invite.From()
	require.Equal(t, "414451770", mustParam(t, from.Params, "tag"))
}

func TestAckTimeoutByeFallsBackToFrom(t *testing.T) {
	r := testResponder()
	invite := parseRequest(t, []byte(strings.Replace(string(pplsipInvite),
		"Contact: <sip:14500163172166221:5060@212.129.10.158:65145>\r\n", "", 1)))
	bye := r.AckTimeoutBye(invite, r.Reply(invite, nil, nil, Answer)[2], nil, "UDP")
	require.NotNil(t, bye)
	require.Equal(t, "sip:14500163172166221:5060@1.2.3.4", bye.Recipient().String())
}

func TestReplyVariants(t *testing.T) {
	authHeader := `Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`
	register := []byte(strings.ReplaceAll(string(pplsipInvite), "INVITE", "REGISTER"))
	cases := []struct {
		name    string
		variant Variant
		data    []byte
		want    []int
	}{
		{"answer register", Answer, register, []int{200}},
		{"answer invite", Answer, pplsipInvite, []int{100, 180, 200}},
		{"auth register", Auth, register, []int{401}},
		{"auth register with credentials", Auth, withAuth(register, authHeader), []int{200}},
		{"auth invite", Auth, pplsipInvite, []int{401}},
		{"auth invite with credentials", Auth, withAuth(pplsipInvite, authHeader), []int{100, 180, 200}},
		{"busy register", Busy, register, []int{200}},
		{"busy invite", Busy, pplsipInvite, []int{100, 180, 486}},
		{"progress register", Progress, register, []int{200}},
		{"progress invite", Progress, pplsipInvite, []int{100, 183, 200}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resps := testResponder().Reply(parseRequest(t, c.data), nil, nil, c.variant)
			var got []int
			for _, r := range resps {
				got = append(got, int(r.StatusCode()))
			}
			require.Equal(t, c.want, got)
			if c.want[0] == 401 {
				require.Contains(t, resps[0].String(), `WWW-Authenticate: Digest realm="asterisk",nonce="1761350400/aab6286c0303e819fe6038a1b16143f3",opaque="0123456789abcdef",algorithm=md5,qop="auth"`+"\r\n")
			}
		})
	}
}

func TestReplyBusySharesRingingTag(t *testing.T) {
	r := &Responder{Token: sequentialTokens()}
	resps := r.Reply(parseRequest(t, pplsipInvite), nil, nil, Busy)
	ringingTo, _ := resps[1].To()
	busyTo, _ := resps[2].To()
	require.Equal(t, mustParam(t, ringingTo.Params, "tag"), mustParam(t, busyTo.Params, "tag"))
	require.Equal(t, "Busy Here", resps[2].Reason())
	require.Empty(t, resps[2].Body())
}

func TestChallenge(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	resp := testResponder().Challenge(parseRequest(t, pplsipInvite), src)
	require.Equal(t, gosip.StatusCode(401), resp.StatusCode())
	require.Contains(t, resp.String(), "received=203.0.113.10")
}

func TestVariantString(t *testing.T) {
	require.Equal(t, []string{"answer", "progress", "auth", "busy"}, []string{Answer.String(), Progress.String(), Auth.String(), Busy.String()})
	require.Equal(t, Answer, Variants[0])
}

func TestEscalate(t *testing.T) {
	require.Equal(t, Answer, Escalate(Answer, 0))
	require.Equal(t, Progress, Escalate(Answer, 1))
	require.Equal(t, Auth, Escalate(Answer, 2))
	require.Equal(t, Busy, Escalate(Answer, 3))
	// Answer is skipped when wrapping around
	require.Equal(t, Progress, Escalate(Answer, 4))
	require.Equal(t, Progress, Escalate(Busy, 1))
	require.Equal(t, Auth, Escalate(Progress, 1))
	require.Equal(t, Auth, Escalate(Auth, -1), "negative steps keep the variant")
}

func TestAnswerProgressSendsEarlyMedia(t *testing.T) {
	r := &Responder{Token: sequentialTokens()}
	_, progress, ok := r.Answer(parseRequest(t, pplsipInvite), nil, nil, Progress)
	require.Equal(t, gosip.StatusCode(183), progress.StatusCode())
	require.Equal(t, "Session Progress", progress.Reason())
	progressTo, _ := progress.To()
	okTo, _ := ok.To()
	require.Equal(t, mustParam(t, progressTo.Params, "tag"), mustParam(t, okTo.Params, "tag"))
	require.Equal(t, ok.Body(), progress.Body(), "183 carries the SDP answer the 200 confirms")
	require.Contains(t, progress.String(), "Content-Type: application/sdp\r\n")
	require.Contains(t, progress.String(), "Contact: <sip:14500972598112101@1.2.3.4:5060>\r\n")
}

func TestInviteAdvertisesArrivalPort(t *testing.T) {
	// the INVITE reached a high port and its Request-URI names none
	req := parseRequest(t, pplsipInvite)
	local := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 65476}
	ok := testResponder().Reply(req, nil, local, Answer)[2].String()
	require.Contains(t, ok, "Contact: <sip:14500972598112101@1.2.3.4:65476>\r\n")
	bye := testResponder().AckTimeoutBye(req, testResponder().Reply(req, nil, local, Answer)[2], local, "UDP")
	require.Contains(t, bye.String(), "Via: SIP/2.0/UDP 1.2.3.4:65476;")

	// the arrival port wins over a Request-URI port, which is only the fallback
	withPort := []byte(strings.Replace(string(pplsipInvite), "INVITE sip:14500972598112101@1.2.3.4 SIP", "INVITE sip:14500972598112101@1.2.3.4:5080 SIP", 1))
	ok = testResponder().Reply(parseRequest(t, withPort), nil, local, Answer)[2].String()
	require.Contains(t, ok, "Contact: <sip:14500972598112101@1.2.3.4:65476>\r\n")
	ok = testResponder().Reply(parseRequest(t, withPort), nil, nil, Answer)[2].String()
	require.Contains(t, ok, "Contact: <sip:14500972598112101@1.2.3.4:5080>\r\n")
}

func sequentialTokens() func() string {
	n := 0
	return func() string {
		n++
		return strings.Repeat(strconv.Itoa(n%10), 16)
	}
}

func TestInviteToNameUsesLocalAddress(t *testing.T) {
	data := strings.Replace(string(pplsipInvite), "INVITE sip:14500972598112101@1.2.3.4 SIP/2.0", "INVITE sip:14500972598112101@pbx.example.com SIP/2.0", 1)
	req := parseRequest(t, []byte(data))
	local := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5060}

	ok := testResponder().Reply(req, nil, local, Answer)[2].String()
	require.Contains(t, ok, "Contact: <sip:14500972598112101@192.0.2.10:5060>\r\n")
	require.Contains(t, ok, "c=IN IP4 192.0.2.10\r\n")

	// without a local address the old fallback stays
	ok = testResponder().Reply(req, nil, nil, Answer)[2].String()
	require.Contains(t, ok, "c=IN IP4 0.0.0.0\r\n")

	// an IPv4 Request-URI host still wins over the local address
	ok = testResponder().Reply(parseRequest(t, pplsipInvite), nil, local, Answer)[2].String()
	require.Contains(t, ok, "c=IN IP4 1.2.3.4\r\n")

	bye := testResponder().AckTimeoutBye(req, testResponder().Reply(req, nil, local, Answer)[2], local, "UDP")
	require.Contains(t, bye.String(), "Via: SIP/2.0/UDP 192.0.2.10:5060;")
}

func TestCalledNumber(t *testing.T) {
	withURI := func(requestURI, to string) gosip.Request {
		s := strings.Replace(string(pplsipInvite), "INVITE sip:14500972598112101@1.2.3.4 SIP/2.0", "INVITE "+requestURI+" SIP/2.0", 1)
		s = strings.Replace(s, "To: <sip:14500972598112101@1.2.3.4>", "To: "+to, 1)
		return parseRequest(t, []byte(s))
	}
	for _, tc := range []struct {
		name, uri, to, want string
	}{
		{"pplsip", "sip:14500972598112101@1.2.3.4", "<sip:14500972598112101@1.2.3.4>", "14500972598112101"},
		{"plus and separators", "sip:+44(20)7946-0000@1.2.3.4", "<sip:x@1.2.3.4>", "+442079460000"},
		{"international prefix", "sip:00972598112101@1.2.3.4", "<sip:x@1.2.3.4>", "00972598112101"},
		{"extension", "sip:100@1.2.3.4", "<sip:100@1.2.3.4>", "100"},
		{"star code", "sip:*97@1.2.3.4", "<sip:*97@1.2.3.4>", "*97"},
		{"name", "sip:asterisk@1.2.3.4", "<sip:asterisk@1.2.3.4>", ""},
		{"user params", "sip:4930123;phone-context=example.com@1.2.3.4", "<sip:x@1.2.3.4>", "4930123"},
		{"To fallback", "sip:1.2.3.4", "<sip:0049301234@1.2.3.4>", "0049301234"},
		{"bare plus", "sip:+@1.2.3.4", "<sip:x@1.2.3.4>", ""},
		{"plus inside", "sip:12+34@1.2.3.4", "<sip:x@1.2.3.4>", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, CalledNumber(withURI(tc.uri, tc.to)))
		})
	}
}

func TestCalledNumberSkipsRegister(t *testing.T) {
	req := parseRequest(t, []byte("REGISTER sip:1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 5.6.7.8:5060;branch=z9hG4bK1\r\nFrom: <sip:100@1.2.3.4>;tag=a\r\nTo: <sip:100@1.2.3.4>\r\nCall-ID: c1\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n"))
	require.Empty(t, CalledNumber(req))
	require.Empty(t, Describe(req).CalledNumber)
}

func TestMayStart(t *testing.T) {
	for _, s := range []string{"R", "REGI", "REGISTER sip:x SIP/2.0", "OPTIONS", "SIP/", "SIP/2.0 200 OK", "INVITE", "ACK "} {
		require.True(t, MayStart([]byte(s)), s)
	}
	for _, s := range []string{"", "GET ", "POST", "\x16\x03\x01", "SSH-", "reg"} {
		require.False(t, MayStart([]byte(s)), s)
	}
}

func TestReplyRegisterChallenge(t *testing.T) {
	on := true
	RegisterChallengeSet = &on
	t.Cleanup(func() { RegisterChallengeSet = nil })

	authHeader := `Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`
	register := []byte(strings.ReplaceAll(string(pplsipInvite), "INVITE", "REGISTER"))
	for _, v := range Variants {
		resps := testResponder().Reply(parseRequest(t, register), nil, nil, v)
		require.Len(t, resps, 1, v.String())
		require.Equal(t, gosip.StatusCode(401), resps[0].StatusCode(), v.String())
		require.Contains(t, resps[0].String(), "WWW-Authenticate: Digest realm=\"asterisk\"")

		// any credentials are accepted
		resps = testResponder().Reply(parseRequest(t, withAuth(register, authHeader)), nil, nil, v)
		require.Len(t, resps, 1, v.String())
		require.Equal(t, gosip.StatusCode(200), resps[0].StatusCode(), v.String())
	}

	// INVITE is not affected
	resps := testResponder().Reply(parseRequest(t, pplsipInvite), nil, nil, Answer)
	require.Len(t, resps, 3)
}

// read frame 1 of a 2026-10-24 Ochi capture: a UA-less REGISTER sweep
// (23.94.174.242) probing extension 809
var sweepRegister = []byte("REGISTER sip:1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 172.26.196.11:59133;branch=z9hG4bK673996722\r\nMax-Forwards: 70\r\nFrom: <sip:809@1.2.3.4>;tag=411687874\r\nTo: <sip:809@1.2.3.4>\r\nCall-ID: 482170477-788816360-1652260690\r\nCSeq: 1 REGISTER\r\nContact: <sip:809@172.26.196.11:59133>\r\nContent-Length: 0\r\n\r\n")

// read frame 1 of a 2026-10-24 Ochi capture: the minimal OPTIONS liveness
// probe sent from many networks
var minimalOptions = []byte("OPTIONS sip:1@1 SIP/2.0\r\nVia: SIP/2.0/UDP 1:5060;branch=c\r\nFrom: <sip:1@1>;tag=1\r\nTo: <sip:1@1>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")

func setExtensions(t *testing.T, list string) {
	t.Helper()
	ExtensionsSet = &list
	t.Cleanup(func() { ExtensionsSet = nil })
}

func registerFor(ext string) []byte {
	return []byte(strings.ReplaceAll(string(sweepRegister), "809@", ext+"@"))
}

func TestKnownExtension(t *testing.T) {
	require.True(t, KnownExtension("965"), "no list: every extension is known")
	setExtensions(t, "100-120, 200,admin 1000-1010")
	for _, user := range []string{"100", "110", "120", "200", "admin", "1005"} {
		require.True(t, KnownExtension(user), user)
	}
	for _, user := range []string{"99", "121", "201", "965", "1", "root", "!12129612050", "100-120"} {
		require.False(t, KnownExtension(user), user)
	}
}

func statusCodes(resps []gosip.Response) []int {
	var got []int
	for _, r := range resps {
		got = append(got, int(r.StatusCode()))
	}
	return got
}

func TestReplyUnknownExtension(t *testing.T) {
	r := testResponder()
	// off by default: every extension registers
	require.Equal(t, []int{200}, statusCodes(r.Reply(parseRequest(t, registerFor("965")), nil, nil, Answer)))
	require.Equal(t, []int{200}, statusCodes(r.Reply(parseRequest(t, minimalOptions), nil, nil, Answer)))

	setExtensions(t, "100-120,200")
	cases := []struct {
		name    string
		data    []byte
		variant Variant
		want    []int
	}{
		{"known register", registerFor("100"), Answer, []int{200}},
		{"known register auth variant", registerFor("110"), Auth, []int{401}},
		{"unknown register", registerFor("965"), Answer, []int{404}},
		{"unknown register auth variant", registerFor("965"), Auth, []int{404}},
		{"unknown options user", minimalOptions, Answer, []int{404}},
		{"known options user", []byte(strings.ReplaceAll(string(minimalOptions), "sip:1@1 ", "sip:200@1.2.3.4 ")), Answer, []int{200}},
		{"options without user", []byte(strings.ReplaceAll(string(minimalOptions), "sip:1@1 ", "sip:1.2.3.4 ")), Answer, []int{200}},
		{"invite dial string unaffected", pplsipInvite, Answer, []int{100, 180, 200}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resps := r.Reply(parseRequest(t, c.data), nil, nil, c.variant)
			require.Equal(t, c.want, statusCodes(resps))
			if c.want[0] == 404 {
				require.Equal(t, "Not Found", resps[0].Reason())
				to, _ := resps[0].To()
				require.True(t, to.Params.Has("tag"))
			}
		})
	}

	// with sip.register_challenge on, known extensions are challenged and
	// unknown ones still get 404
	on := true
	RegisterChallengeSet = &on
	t.Cleanup(func() { RegisterChallengeSet = nil })
	require.Equal(t, []int{401}, statusCodes(r.Reply(parseRequest(t, registerFor("100")), nil, nil, Answer)))
	require.Equal(t, []int{404}, statusCodes(r.Reply(parseRequest(t, registerFor("965")), nil, nil, Answer)))
}

// read frame 1 of a 2026-10-24 Ochi capture: the dial fleet (153.75.83.88)
// with SQL injection in its users, a forged User-Agent and a Zoiper SDP
var fleetInvite = []byte("INVITE sip:+3908351673002@1.2.3.4:7666 SIP/2.0\r\nVia: SIP/2.0/UDP 153.75.83.88:24262;branch=z9hG4bK-524287-1---ad98d9194f20b265;rport\r\nMax-Forwards: 70\r\nFrom: \"15714881666\" <sip:')or('x'='x@1.2.3.4>;tag=c586bd73\r\nTo: <sip:+3908351673002@1.2.3.4>\r\nCall-ID: Htieaz075Awe3IcNWwkXHZ..\r\nCSeq: 101 INVITE\r\nContact: <sip:')or('x'='x@153.75.83.88:24262;transport=UDP>\r\nUser-Agent: Yealink SIP-T46S\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\nSupported: replaces, timer, 100rel, norefersub\r\nP-Preferred-Identity: <sip:')or('x'='x@1.2.3.4>\r\nAllow-Events: presence, kpml, talk\r\nContent-Type: application/sdp\r\nContent-Length: 296\r\n\r\nv=0\r\no=Z 0 0 IN IP4 153.75.83.88\r\ns=Zoiper\r\nc=IN IP4 153.75.83.88\r\nt=0 0\r\nm=audio 10991 RTP/AVP 0 8 18 9 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:18 G729/8000\r\na=fmtp:18 annexb=no\r\na=rtpmap:9 G722/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendrecv\r\n")

func TestToolFleetTells(t *testing.T) {
	fleet := string(fleetInvite)
	require.Equal(t, "sqli-from", Tool(parseRequest(t, fleetInvite)))
	require.Equal(t, "sqli-from", Describe(parseRequest(t, fleetInvite)).Tool)

	// the injection in any one of the three headers is enough
	clean := strings.ReplaceAll(fleet, "')or('x'='x", "15714881666")
	for _, header := range []string{"From: \"15714881666\" <sip:", "Contact: <sip:", "P-Preferred-Identity: <sip:"} {
		data := strings.Replace(clean, header+"15714881666", header+"')OR('x'='x", 1)
		require.Equal(t, "sqli-from", Tool(parseRequest(t, []byte(data))), header)
	}

	// without the injection the Zoiper SDP behind a phone User-Agent remains
	require.Equal(t, "zoiper-fleet", Tool(parseRequest(t, []byte(clean))))
	// a real Zoiper says so in its User-Agent
	realZoiper := strings.Replace(clean, "User-Agent: Yealink SIP-T46S", "User-Agent: Zoiper rev.12345", 1)
	require.Equal(t, "", Tool(parseRequest(t, []byte(realZoiper))))
	// a known tool User-Agent wins over the fleet tells
	pplsip := strings.Replace(fleet, "User-Agent: Yealink SIP-T46S", "User-Agent: pplsip", 1)
	require.Equal(t, "pplsip", Tool(parseRequest(t, []byte(pplsip))))
}

func TestToolSippts(t *testing.T) {
	require.Equal(t, "sippts", Tool(parseRequest(t, sweepRegister)))

	withUA := strings.Replace(string(sweepRegister), "Content-Length: 0\r\n", "User-Agent: MicroSIP/3.21.3\r\nContent-Length: 0\r\n", 1)
	require.Equal(t, "", Tool(parseRequest(t, []byte(withUA))), "a User-Agent rules out the UA-less sippts tell")
	otherCallID := strings.Replace(string(sweepRegister), "Call-ID: 482170477-788816360-1652260690", "Call-ID: abc@host", 1)
	require.Equal(t, "", Tool(parseRequest(t, []byte(otherCallID))))
	otherBranch := strings.Replace(string(sweepRegister), "branch=z9hG4bK673996722", "branch=z9hG4bK-67399a", 1)
	require.Equal(t, "", Tool(parseRequest(t, []byte(otherBranch))))
	// the minimal OPTIONS probe carries none of the tells
	require.Equal(t, "", Tool(parseRequest(t, minimalOptions)))
}

func TestCalledNumberRefer(t *testing.T) {
	refer := func(referTo string) gosip.Request {
		data := strings.Replace(string(pplsipInvite), "INVITE sip:", "REFER sip:", 1)
		data = strings.Replace(data, "CSeq: 1 INVITE", "CSeq: 2 REFER", 1)
		if referTo != "" {
			data = strings.Replace(data, "User-Agent: pplsip\r\n", "User-Agent: pplsip\r\nRefer-To: "+referTo+"\r\n", 1)
		}
		return parseRequest(t, []byte(data))
	}
	cases := []struct{ referTo, want string }{
		{"<sip:0044203769291@1.2.3.4;user=phone>", "0044203769291"},
		{"sip:+44-20-3769-291@1.2.3.4", "+44203769291"},
		{`"x" <sip:900970597692790@1.2.3.4?Replaces=abc%3Bto-tag%3D1>`, "900970597692790"},
		{"<sip:admin@1.2.3.4>", ""},
		{"<sip:1.2.3.4>", ""},
		// without Refer-To the Request-URI is the number, as for other methods
		{"", "14500972598112101"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, CalledNumber(refer(c.referTo)), c.referTo)
	}
}
