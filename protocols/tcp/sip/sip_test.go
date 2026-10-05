package sip

import (
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

func TestReplyInviteChallenge(t *testing.T) {
	resps := testResponder().Reply(parseRequest(t, pplsipInvite))
	require.Len(t, resps, 1)
	require.Equal(t, "SIP/2.0 401 Unauthorized\r\n"+
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n"+
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n"+
		"To: <sip:14500972598112101@1.2.3.4>;tag=0123456789abcdef\r\n"+
		"Call-ID: 1492163839-465544234-336545636\r\n"+
		"CSeq: 1 INVITE\r\n"+
		"Server: Asterisk PBX 18.20.0\r\n"+
		"WWW-Authenticate: Digest realm=\"asterisk\",nonce=\"0123456789abcdef\",algorithm=MD5,qop=\"auth\"\r\n"+
		"Content-Length: 0\r\n\r\n", resps[0].String())
}

func TestReplyAuthenticatedRejected(t *testing.T) {
	for _, header := range []string{
		`Authorization: Digest username="1000",realm="asterisk",nonce="0123456789abcdef",uri="sip:14500972598112101@1.2.3.4",response="d41d8cd98f00b204e9800998ecf8427e",algorithm=MD5`,
		`Proxy-Authorization: Digest username="1000",realm="asterisk",nonce="x",uri="sip:1.2.3.4",response="00"`,
	} {
		req := parseRequest(t, withAuth(pplsipInvite, header))
		require.Equal(t, "1000", Credentials(req))
		resps := testResponder().Reply(req)
		require.Len(t, resps, 1)
		require.Equal(t, gosip.StatusCode(403), resps[0].StatusCode())
		require.Equal(t, "Forbidden", resps[0].Reason())
		require.Empty(t, resps[0].GetHeaders("WWW-Authenticate"))
	}
}

func TestReplyOptions(t *testing.T) {
	req := parseRequest(t, []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport\r\n"+
		"From: \"sipvicious\"<sip:100@1.1.1.1>;tag=abc\r\n"+
		"To: \"sipvicious\"<sip:100@1.1.1.1>\r\n"+
		"Call-ID: 12345\r\n"+
		"CSeq: 1 OPTIONS\r\n"+
		"Content-Length: 0\r\n\r\n"))
	resps := testResponder().Reply(req)
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
	out := testResponder().Reply(req)[0].String()
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
		"BYE":       481,
		"CANCEL":    481,
		"REGISTER":  401,
		"SUBSCRIBE": 401,
		"MESSAGE":   401,
	}
	for method, want := range cases {
		data := strings.ReplaceAll(string(pplsipInvite), "INVITE", method)
		resps := testResponder().Reply(parseRequest(t, []byte(data)))
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

	resp := testResponder().Reply(parseRequest(t, pplsipInvite))[0]
	info = Describe(resp)
	require.Equal(t, 401, info.Status)
	require.Equal(t, "Asterisk PBX 18.20.0", info.UserAgent)
	require.Empty(t, info.Method)
}

func TestCredentialsIgnoresNonDigest(t *testing.T) {
	req := parseRequest(t, withAuth(pplsipInvite, `Authorization: Basic dXNlcjpwYXNz`))
	require.Empty(t, Credentials(req))
}
