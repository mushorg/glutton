package tcp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/recall"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"
	"github.com/stretchr/testify/require"
)

// read frame 1 of Ochi event 748a8b05-6a95-4592-94b5-15cb4ea65164 (pplsip toll-fraud INVITE), sent over TCP
var sipInviteRead1 = []byte("INVITE sip:14500972598112101@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917159\r\nMax-Forwards: 70\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 1 INVITE\r\nContact: <sip:14500163172166221:5060@212.129.10.158:65145>\r\nUser-Agent: pplsip\r\nContent-Type: application/sdp\r\nContent-Length: 211\r\n\r\nv=0\r\no=14500163172166221:5060 16264 18299 IN IP4 0.0.0.0\r\ns=pplsip\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 25282 RTP/AVP 100 6 0 8 3 18 5 101\r\na=rtpmap:0 pcmu/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\n")

// read frame 1 of Ochi event f06fe1f1-27fc-4f49-8d2d-77d2f31fdf1f ("VOIP" extension scanner), sent over TCP
var sipRegisterRead1 = []byte("REGISTER sip:1.2.3.4:5060 SIP/2.0\r\nTo: <sip:100@1.2.3.4>\r\nFrom: <sip:100@1.2.3.4>;tag=e5f4a9860666e4f7a\r\nVia: SIP/2.0/TCP 185.243.5.243:49618;branch=z9hG4bK-d87543-987333414-1--d87543-;rport\r\nCall-ID: e5f4a986066756e4f7a\r\nCSeq: 1 REGISTER\r\nContact: <sip:100@185.243.5.243:49618>\r\nExpires: 3600\r\nMax-Forwards: 70\r\nUser-Agent: VOIP\r\nContent-Length: 0\r\n\r\n")

var sipAckRead = []byte("ACK sip:14500972598112101@1.2.3.4:5060 SIP/2.0\r\nVia: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917160\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n")

var sipByeRead = []byte("BYE sip:14500972598112101@1.2.3.4:5060 SIP/2.0\r\nVia: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917161\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n")

func startSIP(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	stubSIPRecall(t)
	return startSIPFrom(t, nil)
}

// stubSIPRecall gives the test a fresh visit store and returns a function
// that advances its clock.
func stubSIPRecall(t *testing.T) func(time.Duration) {
	t.Helper()
	now := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	orig := sipRecall
	sipRecall = recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	t.Cleanup(func() { sipRecall = orig })
	return func(d time.Duration) { now = now.Add(d) }
}

// startSIPFrom runs the handler on a pipe whose server side reports remote
// as the client address; nil keeps the pipe's address.
func startSIPFrom(t *testing.T, remote net.Addr) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	if remote != nil {
		serverConn = connWithRemote{Conn: serverConn, remote: remote}
	}
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

func TestHandleSIPTCPRegisterThenCall(t *testing.T) {
	client, hp, done := startSIP(t)

	_, err := client.Write(sipRegisterRead1)
	require.NoError(t, err)
	registered := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(registered, "SIP/2.0 200 OK\r\n"), registered)
	require.Contains(t, registered, "Contact: <sip:100@185.243.5.243:49618>;expires=3600\r\n")

	_, err = client.Write(sipInviteRead1)
	require.NoError(t, err)
	trying := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(trying, "SIP/2.0 100 Trying\r\n"), trying)
	require.Contains(t, trying, "Via: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n")
	ringing := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(ringing, "SIP/2.0 180 Ringing\r\n"), ringing)
	answered := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(answered, "SIP/2.0 200 OK\r\n"), answered)
	require.Contains(t, answered, "To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n")
	require.Contains(t, answered, "Content-Type: application/sdp\r\n")
	require.Contains(t, answered, "m=audio 18204 RTP/AVP 0 101\r\n")

	_, err = client.Write(sipAckRead)
	require.NoError(t, err)
	_, err = client.Write(sipByeRead)
	require.NoError(t, err)
	bye := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(bye, "SIP/2.0 200 OK\r\n"), bye)
	require.Contains(t, bye, "CSeq: 2 BYE\r\n")

	require.NoError(t, client.Close())
	produced := waitSIP(t, hp, done)
	require.Equal(t, "sip", produced.protocol)
	require.Equal(t, connection.EndClientClose, produced.endReason)

	register := parsedSIP{From: "sip:100@1.2.3.4", To: "sip:100@1.2.3.4", CallID: "e5f4a986066756e4f7a"}
	call := parsedSIP{From: "sip:14500163172166221:5060@1.2.3.4", To: "sip:14500972598112101@1.2.3.4", CallID: "1492163839-465544234-336545636"}
	read := func(f parsedSIP, method, path, ua string, payload []byte) parsedSIP {
		f.Direction, f.Command, f.Path, f.UserAgent, f.Payload = "read", method, path, ua, payload
		return f
	}
	write := func(f parsedSIP, status, payload string) parsedSIP {
		f.Direction, f.Status, f.UserAgent, f.Payload = "write", status, "Asterisk PBX 18.20.0", []byte(payload)
		f.Variant, f.Visit = "answer", 1
		return f
	}
	require.Equal(t, []parsedSIP{
		read(register, "REGISTER", "sip:1.2.3.4:5060", "VOIP", sipRegisterRead1),
		write(register, "200", registered),
		read(call, "INVITE", "sip:14500972598112101@1.2.3.4", "pplsip", sipInviteRead1),
		write(call, "100", trying),
		write(call, "180", ringing),
		write(call, "200", answered),
		read(call, "ACK", "sip:14500972598112101@1.2.3.4:5060", "", sipAckRead),
		read(call, "BYE", "sip:14500972598112101@1.2.3.4:5060", "", sipByeRead),
		write(call, "200", bye),
	}, produced.decoded)
}

func TestHandleSIPTCPRegisterBareLF(t *testing.T) {
	client, hp, done := startSIP(t)
	register := []byte(strings.ReplaceAll(string(sipRegisterRead1), "\r\n", "\n"))

	_, err := client.Write(register)
	require.NoError(t, err)
	registered := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(registered, "SIP/2.0 200 OK\r\n"), registered)
	require.Contains(t, registered, "Contact: <sip:100@185.243.5.243:49618>;expires=3600\r\n")
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	events, ok := produced.decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "REGISTER", events[0].Command)
	require.Equal(t, register, events[0].Payload) // raw wire bytes
	require.Equal(t, "200", events[1].Status)
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

func TestHandleSIPTCPReturningSourceGetsNextVariant(t *testing.T) {
	advance := stubSIPRecall(t)
	remote := staticAddr{"185.243.5.243:49618"}
	register := func() (string, producedTCP) {
		client, hp, done := startSIPFrom(t, remote)
		_, err := client.Write(sipRegisterRead1)
		require.NoError(t, err)
		reply := readSIPReply(t, client)
		require.NoError(t, client.Close())
		return reply, waitSIP(t, hp, done)
	}

	reply, produced := register()
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 200 OK\r\n"), reply)
	events := produced.decoded.([]parsedSIP)
	require.Equal(t, "answer", events[1].Variant)
	require.Equal(t, 1, events[1].Visit)
	require.Empty(t, events[0].Variant, "reads carry no variant")

	advance(time.Hour)
	reply, produced = register()
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 401 Unauthorized\r\n"), reply)
	events = produced.decoded.([]parsedSIP)
	require.Equal(t, "auth", events[1].Variant)
	require.Equal(t, 2, events[1].Visit)

	advance(time.Hour)
	v := sipRecall.Begin("sip", net.ParseIP("185.243.5.243"), len(sipproto.Variants))
	require.Equal(t, 3, v.Number)
	require.Equal(t, "auth", v.Previous.Variant)
	require.Equal(t, []string{"REGISTER"}, v.Previous.Commands)
	require.Equal(t, "VOIP", v.Previous.UserAgent)
}
