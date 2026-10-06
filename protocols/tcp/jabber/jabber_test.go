package jabber

import (
	"encoding/base64"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"
)

const streamHeader = "<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

func TestNextFrame(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00admin\x00hunter2"))
	auth := "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>" + plain + "</auth>"

	tests := []struct {
		name  string
		in    string
		frame string
		rest  string
		ok    bool
	}{
		{name: "stream header without newline", in: streamHeader, frame: streamHeader, ok: true},
		{name: "header then stanza", in: streamHeader + auth, frame: streamHeader, rest: auth, ok: true},
		{name: "complete stanza", in: " " + auth + "<presence/>", frame: " " + auth, rest: "<presence/>", ok: true},
		{name: "self-closing", in: "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", frame: "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", ok: true},
		{name: "nested", in: "<iq type='set'><query xmlns='jabber:iq:auth'><username>u</username></query></iq>", frame: "<iq type='set'><query xmlns='jabber:iq:auth'><username>u</username></query></iq>", ok: true},
		{name: "stream close", in: "</stream:stream>", frame: "</stream:stream>", ok: true},
		{name: "partial header", in: "<?xml version='1.0'?><stream:str", rest: "<?xml version='1.0'?><stream:str"},
		{name: "partial stanza body", in: "<auth mechanism='PLAIN'>AGFk", rest: "<auth mechanism='PLAIN'>AGFk"},
		{name: "whitespace only", in: "  \n", rest: "  \n"},
		{name: "empty", in: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, rest, ok, err := NextFrame([]byte(tt.in))
			require.NoError(t, err)
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.frame, string(frame))
			require.Equal(t, tt.rest, string(rest))
		})
	}
}

func TestNextFrameMalformed(t *testing.T) {
	for _, in := range []string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"<a></b><c>",
		"</iq>",
		"<a b=c>",
	} {
		_, _, ok, err := NextFrame([]byte(in))
		require.False(t, ok, in)
		require.ErrorIs(t, err, ErrMalformed, in)
	}
}

func TestParseStanza(t *testing.T) {
	st, err := ParseStanza([]byte(streamHeader))
	require.NoError(t, err)
	require.Equal(t, Stanza{Name: "stream", Space: NSClient, To: "example.com"}, st)

	st, err = ParseStanza([]byte("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGEAYg==</auth>"))
	require.NoError(t, err)
	require.Equal(t, Stanza{Name: "auth", Space: NSSASL, Mechanism: "PLAIN", Text: "AGEAYg=="}, st)

	st, err = ParseStanza([]byte("<iq type='set' id='auth1'><query xmlns='jabber:iq:auth'><username>bill</username><password>Calli0pe</password><resource>globe</resource></query></iq>"))
	require.NoError(t, err)
	require.Equal(t, Stanza{Name: "iq", ID: "auth1", Type: "set", QueryNS: NSIQAuth, Username: "bill", Password: "Calli0pe", Resource: "globe"}, st)

	st, err = ParseStanza([]byte("</stream:stream>"))
	require.NoError(t, err)
	require.Equal(t, CmdStreamEnd, st.Name)

	_, err = ParseStanza(nil)
	require.Error(t, err)
}

func TestDecodePlain(t *testing.T) {
	authz, user, pass, err := DecodePlain(base64.StdEncoding.EncodeToString([]byte("az\x00root\x00pa\x00ss")))
	require.NoError(t, err)
	require.Equal(t, "az", authz)
	require.Equal(t, "root", user)
	require.Equal(t, "pa\x00ss", pass)

	_, _, _, err = DecodePlain("!!!")
	require.Error(t, err)
	_, _, _, err = DecodePlain(base64.StdEncoding.EncodeToString([]byte("nonul")))
	require.Error(t, err)
}

func TestResponses(t *testing.T) {
	require.Equal(t,
		"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='abc' from='example.com' version='1.0' xml:lang='en'>",
		string(StreamHeader("abc", "example.com")))
	// Attacker-controlled "to" must not break out of the attribute.
	require.Contains(t, string(StreamHeader("abc", "x' evil='1")), "from='x&#39; evil=&#39;1'")

	require.Equal(t,
		"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms><auth xmlns='http://jabber.org/features/iq-auth'/></stream:features>",
		string(Features(true)))
	require.NotContains(t, string(Features(false)), "starttls")

	require.Equal(t, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>", string(SASLFailure("not-authorized")))

	// Every non-header response is well-formed XML on its own.
	for _, b := range [][]byte{Features(true), Proceed(), SASLFailure("not-authorized"), IQAuthFields("a1"), IQError("a1", "auth", "not-authorized")} {
		require.NoError(t, xml.Unmarshal(b, new(struct{})), string(b))
	}
}
