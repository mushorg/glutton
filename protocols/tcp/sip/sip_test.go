package sip

import (
	"net"
	"strings"
	"testing"

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

func testResponder() *Responder {
	return &Responder{Token: func() string { return "0123456789abcdef" }}
}

func TestReplyInviteAnswered(t *testing.T) {
	resps := testResponder().Reply(parseRequest(t, pplsipInvite), nil)
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
		resps := testResponder().Reply(req, nil)
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
		resps := testResponder().Reply(req, nil)
		require.Len(t, resps, 1)
		require.Equal(t, gosip.StatusCode(403), resps[0].StatusCode())
		require.Equal(t, "Forbidden", resps[0].Reason())
		require.Empty(t, resps[0].GetHeaders("WWW-Authenticate"))
	}
}

func TestReplyRegisterWithCredentialsAccepted(t *testing.T) {
	register := []byte(strings.ReplaceAll(string(pplsipInvite), "INVITE", "REGISTER"))
	req := parseRequest(t, withAuth(register, `Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`))
	resps := testResponder().Reply(req, nil)
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
	resps := testResponder().Reply(req, nil)
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
	out := testResponder().Reply(req, nil)[0].String()
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
		resps := testResponder().Reply(parseRequest(t, []byte(data)), nil)
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
		Method:    "INVITE",
		URI:       "sip:14500972598112101@1.2.3.4",
		From:      "sip:14500163172166221:5060@1.2.3.4",
		To:        "sip:14500972598112101@1.2.3.4",
		CallID:    "1492163839-465544234-336545636",
		UserAgent: "pplsip",
	}, info)

	resp := testResponder().Reply(parseRequest(t, pplsipInvite), nil)[2]
	info = Describe(resp)
	require.Equal(t, 200, info.Status)
	require.Equal(t, "Asterisk PBX 18.20.0", info.UserAgent)
	require.Empty(t, info.Method)
}

func TestCredentialsIgnoresNonDigest(t *testing.T) {
	req := parseRequest(t, withAuth(pplsipInvite, `Authorization: Basic dXNlcjpwYXNz`))
	require.Empty(t, Credentials(req))
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
		out := testResponder().Reply(req, c.src)[0].String()
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
	ok := r.Reply(invite, nil)[2]

	bye := r.AckTimeoutBye(invite, ok)
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
	bye := r.AckTimeoutBye(invite, r.Reply(invite, nil)[2])
	require.NotNil(t, bye)
	require.Equal(t, "sip:14500163172166221:5060@1.2.3.4", bye.Recipient().String())
}
