package tcp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"
	"github.com/stretchr/testify/require"
)

// read frame 1 of Ochi event 748a8b05-6a95-4592-94b5-15cb4ea65164 (pplsip toll-fraud INVITE), sent over TCP
var sipInviteRead1 = []byte("INVITE sip:14500972598112101@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917159\r\nMax-Forwards: 70\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 1 INVITE\r\nContact: <sip:14500163172166221:5060@212.129.10.158:65145>\r\nUser-Agent: pplsip\r\nContent-Type: application/sdp\r\nContent-Length: 211\r\n\r\nv=0\r\no=14500163172166221:5060 16264 18299 IN IP4 0.0.0.0\r\ns=pplsip\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 25282 RTP/AVP 100 6 0 8 3 18 5 101\r\na=rtpmap:0 pcmu/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\n")

func sipInviteWithAuth() []byte {
	digest := `Authorization: Digest username="1000",realm="asterisk",nonce="feedface",uri="sip:14500972598112101@1.2.3.4",response="d41d8cd98f00b204e9800998ecf8427e"`
	s := strings.Replace(string(sipInviteRead1), "CSeq: 1 INVITE", "CSeq: 2 INVITE", 1)
	return []byte(strings.Replace(s, "User-Agent: pplsip\r\n", "User-Agent: pplsip\r\n"+digest+"\r\n", 1))
}

func startSIP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	responder := &sipproto.Responder{Token: func() string { return "feedface" }}
	done := make(chan error, 1)
	go func() {
		done <- handleSIP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp, responder)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func readSIPReply(t *testing.T, conn net.Conn) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return string(buf[:n])
}

func waitSIP(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	return produced
}

func TestHandleSIPTCPChallengeThenForbidden(t *testing.T) {
	client, hp, done := startSIP(t)

	_, err := client.Write(sipInviteRead1)
	require.NoError(t, err)
	challenge := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(challenge, "SIP/2.0 401 Unauthorized\r\n"), challenge)
	require.Contains(t, challenge, "Via: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n")
	require.Contains(t, challenge, "To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n")
	require.Contains(t, challenge, `WWW-Authenticate: Digest realm="asterisk",nonce="feedface",algorithm=MD5,qop="auth"`)

	_, err = client.Write(sipInviteWithAuth())
	require.NoError(t, err)
	forbidden := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(forbidden, "SIP/2.0 403 Forbidden\r\n"), forbidden)
	require.Contains(t, forbidden, "CSeq: 2 INVITE\r\n")

	require.NoError(t, client.Close())
	produced := waitSIP(t, hp, done)
	require.Equal(t, "sip", produced.protocol)
	require.Equal(t, connection.EndClientClose, produced.endReason)

	common := parsedSIP{
		From:   "sip:14500163172166221:5060@1.2.3.4",
		To:     "sip:14500972598112101@1.2.3.4",
		CallID: "1492163839-465544234-336545636",
	}
	read := func(username string, payload []byte) parsedSIP {
		f := common
		f.Direction, f.Command, f.Path, f.UserAgent, f.Username, f.Payload = "read", "INVITE", "sip:14500972598112101@1.2.3.4", "pplsip", username, payload
		return f
	}
	write := func(status, payload string) parsedSIP {
		f := common
		f.Direction, f.Status, f.UserAgent, f.Payload = "write", status, "Asterisk PBX 18.20.0", []byte(payload)
		return f
	}
	require.Equal(t, []parsedSIP{
		read("", sipInviteRead1),
		write("401", challenge),
		read("1000", sipInviteWithAuth()),
		write("403", forbidden),
	}, produced.decoded)
}

func TestHandleSIPTCPEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startSIP(t)
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	require.Equal(t, "sip", produced.protocol)
	require.Empty(t, produced.decoded)
}

func TestHandleSIPTCPMalformedStillProduces(t *testing.T) {
	client, hp, done := startSIP(t)
	_, err := client.Write([]byte("not-sip\r\n\r\n"))
	require.NoError(t, err)

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Equal(t, []parsedSIP{{Direction: "read", Payload: []byte("not-sip\r\n\r\n")}}, produced.decoded)
	require.Equal(t, connection.EndReadError, produced.endReason)
}
