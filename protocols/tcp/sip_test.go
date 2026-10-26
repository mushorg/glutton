package tcp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
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

type fakeSIPTimer struct {
	ts      *fakeSIPTimers
	d       time.Duration
	f       func()
	stopped bool
	fired   bool
}

func (ft *fakeSIPTimer) Stop() bool {
	ft.ts.mu.Lock()
	defer ft.ts.mu.Unlock()
	ft.stopped = true
	return !ft.fired
}

// fakeSIPTimers hands out timers the test fires by hand.
type fakeSIPTimers struct {
	mu     sync.Mutex
	timers []*fakeSIPTimer
}

func (ts *fakeSIPTimers) afterFunc(d time.Duration, f func()) sipTimer {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ft := &fakeSIPTimer{ts: ts, d: d, f: f}
	ts.timers = append(ts.timers, ft)
	return ft
}

// pending returns the durations of armed timers, in creation order.
func (ts *fakeSIPTimers) pending() []time.Duration {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := []time.Duration{}
	for _, ft := range ts.timers {
		if !ft.stopped && !ft.fired {
			out = append(out, ft.d)
		}
	}
	return out
}

// fire runs the oldest armed timer of duration d, waiting briefly for the
// handler to arm it (it may still be finishing the write the test just
// read). It returns once the handler has taken the callback.
func (ts *fakeSIPTimers) fire(t *testing.T, d time.Duration) {
	t.Helper()
	var target *fakeSIPTimer
	require.Eventually(t, func() bool {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		for _, ft := range ts.timers {
			if !ft.stopped && !ft.fired && ft.d == d {
				target = ft
				ft.fired = true
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond, "no armed %v timer", d)
	target.f()
}

// sipRing is the ringing delay in tests.
const sipRing = 3 * time.Second

// stubSIPTimers gives the test hand-fired timers; INVITEs ring for sipRing
// and none are rejected.
func stubSIPTimers(t *testing.T) *fakeSIPTimers {
	t.Helper()
	timers := &fakeSIPTimers{}
	origAfter, origRing, origLimit := sipTCPAfterFunc, sipTCPRingDelay, sipproto.RejectLimit
	sipTCPAfterFunc = timers.afterFunc
	sipTCPRingDelay = func() time.Duration { return sipRing }
	sipproto.RejectLimit = 0
	t.Cleanup(func() {
		sipTCPAfterFunc, sipTCPRingDelay, sipproto.RejectLimit = origAfter, origRing, origLimit
	})
	return timers
}

// startSIPFrom runs the handler on a pipe whose server side reports remote
// as the client address; nil keeps the pipe's address.
func startSIPFrom(t *testing.T, remote net.Addr) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	return startSIPWith(t, remote, connection.Metadata{})
}

func startSIPWith(t *testing.T, remote net.Addr, md connection.Metadata) (net.Conn, *fakeHoneypot, chan error) {
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
		done <- handleSIP(context.Background(), serverConn, md, &recordingLogger{}, hp, responder)
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
	timers := stubSIPTimers(t)
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
	timers.fire(t, sipRing)
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
	require.Empty(t, timers.pending(), "the ACK stopped the ACK wait")

	require.NoError(t, client.Close())
	produced := waitSIP(t, hp, done)
	require.Equal(t, "sip", produced.protocol)
	require.Equal(t, connection.EndClientClose, produced.endReason)

	register := parsedSIP{From: "sip:100@1.2.3.4", To: "sip:100@1.2.3.4", CallID: "e5f4a986066756e4f7a"}
	call := parsedSIP{From: "sip:14500163172166221:5060@1.2.3.4", To: "sip:14500972598112101@1.2.3.4", CallID: "1492163839-465544234-336545636"}
	read := func(f parsedSIP, method, path, ua string, payload []byte) parsedSIP {
		f.Direction, f.Command, f.Path, f.UserAgent, f.Payload = "read", method, path, ua, payload
		if method != "REGISTER" {
			f.CalledNumber = "14500972598112101"
		}
		switch {
		case ua == "pplsip":
			f.Tool = "pplsip"
		case ua == "" && f.CallID == call.CallID:
			// UA-less in-dialog requests keep sippts' Call-ID and branch habit
			f.Tool = "sippts"
		}
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

func TestHandleSIPTCPMalformedMessageKeepsSession(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	// framed (no Content-Length means no body) but not SIP
	_, err := client.Write([]byte("not-sip\r\n\r\n"))
	require.NoError(t, err)
	_, err = client.Write(sipRegisterRead1)
	require.NoError(t, err)
	reply := readSIPReply(t, client)
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 200 OK\r\n"), reply)
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	events := produced.decoded.([]parsedSIP)
	require.Len(t, events, 3)
	require.Equal(t, parsedSIP{Direction: "read", Payload: []byte("not-sip\r\n\r\n")}, events[0])
	require.Equal(t, "REGISTER", events[1].Command)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleSIPTCPFramingErrorStillProduces(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	bad := []byte("INVITE sip:1@1.2.3.4 SIP/2.0\r\nContent-Length: abc\r\n\r\n")
	_, err := client.Write(bad)
	require.NoError(t, err)

	produced := waitSIP(t, hp, done)
	// the frame ends at the header the framer rejected
	require.Equal(t, []parsedSIP{{Direction: "read", Payload: bad[:len(bad)-2]}}, produced.decoded)
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

	// visit 2 (progress) accepts REGISTER like answer
	advance(time.Hour)
	reply, produced = register()
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 200 OK\r\n"), reply)
	events = produced.decoded.([]parsedSIP)
	require.Equal(t, "progress", events[1].Variant)
	require.Equal(t, 2, events[1].Visit)

	advance(time.Hour)
	reply, produced = register()
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 401 Unauthorized\r\n"), reply)
	events = produced.decoded.([]parsedSIP)
	require.Equal(t, "auth", events[1].Variant)
	require.Equal(t, 3, events[1].Visit)

	advance(time.Hour)
	v := sipRecall.Begin("sip", net.ParseIP("185.243.5.243"), len(sipproto.Variants))
	require.Equal(t, 4, v.Number)
	require.Equal(t, "auth", v.Previous.Variant)
	require.Equal(t, []string{"REGISTER"}, v.Previous.Commands)
	require.Equal(t, "VOIP", v.Previous.UserAgent)
}

// sipInviteFor is the pplsip INVITE with its Call-ID replaced.
func sipInviteFor(callID string) []byte {
	return []byte(strings.ReplaceAll(string(sipInviteRead1), "1492163839-465544234-336545636", callID))
}

func sipInDialog(method string, seq int, callID string) []byte {
	return []byte(method + " sip:14500972598112101@1.2.3.4:5060 SIP/2.0\r\nVia: SIP/2.0/TCP 0.0.0.0:65145;branch=z9hG4bK951917159\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>\r\nCall-ID: " + callID + "\r\nCSeq: " + strconv.Itoa(seq) + " " + method + "\r\nContent-Length: 0\r\n\r\n")
}

var sipOptionsRead = []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 5.6.7.8:5060;branch=z9hG4bK-opt\r\nFrom: <sip:100@1.2.3.4>;tag=o1\r\nTo: <sip:100@1.2.3.4>\r\nCall-ID: opt-1\r\nCSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n")

func requireStatus(t *testing.T, reply string, status string) {
	t.Helper()
	require.True(t, strings.HasPrefix(reply, "SIP/2.0 "+status+" "), reply)
}

func statuses(events []parsedSIP) []string {
	out := []string{}
	for _, e := range events {
		if e.Direction == "write" {
			out = append(out, e.Status+e.Command)
		} else {
			out = append(out, "<"+e.Command)
		}
	}
	return out
}

func TestHandleSIPTCPSplitAndPipelined(t *testing.T) {
	timers := stubSIPTimers(t)
	client, hp, done := startSIP(t)

	// an INVITE split mid-header and mid-body
	_, err := client.Write(sipInviteRead1[:100])
	require.NoError(t, err)
	_, err = client.Write(sipInviteRead1[100 : len(sipInviteRead1)-20])
	require.NoError(t, err)
	_, err = client.Write(sipInviteRead1[len(sipInviteRead1)-20:])
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "100")
	requireStatus(t, readSIPReply(t, client), "180")
	timers.fire(t, sipRing)
	requireStatus(t, readSIPReply(t, client), "200")

	// REGISTER and OPTIONS in one segment; the writer goroutine stands in
	// for the client's send buffer, as a pipe write blocks until read
	go func() { _, _ = client.Write(append(append([]byte{}, sipRegisterRead1...), sipOptionsRead...)) }()
	reg := readSIPReply(t, client)
	requireStatus(t, reg, "200")
	require.Contains(t, reg, "CSeq: 1 REGISTER\r\n")
	opt := readSIPReply(t, client)
	requireStatus(t, opt, "200")
	require.Contains(t, opt, "CSeq: 1 OPTIONS\r\n")
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	events := produced.decoded.([]parsedSIP)
	require.Equal(t, []string{"<INVITE", "100", "180", "200", "<REGISTER", "200", "<OPTIONS", "200"}, statuses(events))
	require.Equal(t, sipInviteRead1, events[0].Payload, "the split INVITE is one frame")
	require.Equal(t, "14500972598112101", events[0].CalledNumber)
}

func TestHandleSIPTCPKeepalive(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	_, err := client.Write([]byte("\r\n\r\n"))
	require.NoError(t, err)
	require.Equal(t, "\r\n", readSIPReply(t, client))
	_, err = client.Write(sipOptionsRead)
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "200")
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	require.Equal(t, []string{"<OPTIONS", "200"}, statuses(produced.decoded.([]parsedSIP)), "pings are not frames")
}

func TestHandleSIPTCPRejectsFirstInvites(t *testing.T) {
	timers := stubSIPTimers(t)
	sipproto.RejectLimit = 1
	client, hp, done := startSIPVisit(t, 1)

	_, err := client.Write(sipInviteFor("call-1"))
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "100")
	notFound := readSIPReply(t, client)
	requireStatus(t, notFound, "404")
	require.Contains(t, notFound, "To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n")
	_, err = client.Write(sipInDialog("ACK", 1, "call-1"))
	require.NoError(t, err)

	_, err = client.Write(sipInviteFor("call-2"))
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "100")
	requireStatus(t, readSIPReply(t, client), "180")
	timers.fire(t, sipRing)
	requireStatus(t, readSIPReply(t, client), "200")
	require.NoError(t, client.Close())

	produced := waitSIP(t, hp, done)
	require.Equal(t, []string{"<INVITE", "100", "404", "<ACK", "<INVITE", "100", "180", "200"}, statuses(produced.decoded.([]parsedSIP)))
}

func TestHandleSIPTCPCancelWhileRinging(t *testing.T) {
	timers := stubSIPTimers(t)
	client, hp, done := startSIPVisit(t, 1)

	_, err := client.Write(sipInviteRead1)
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "100")
	requireStatus(t, readSIPReply(t, client), "180")
	_, err = client.Write(sipInDialog("CANCEL", 1, "1492163839-465544234-336545636"))
	require.NoError(t, err)
	cancelOK := readSIPReply(t, client)
	requireStatus(t, cancelOK, "200")
	require.Contains(t, cancelOK, "CSeq: 1 CANCEL\r\n")
	terminated := readSIPReply(t, client)
	requireStatus(t, terminated, "487")
	require.Contains(t, terminated, "CSeq: 1 INVITE\r\n")
	require.Contains(t, terminated, ";tag=feedface\r\n")
	require.Eventually(t, func() bool {
		p := timers.pending()
		return len(p) == 1 && p[0] == sipTCPAckTimeout
	}, time.Second, time.Millisecond, "ringing stopped, the 487 waits for its ACK")

	// an unACKed 487 is not counted against the source
	timers.fire(t, sipTCPAckTimeout)
	require.NoError(t, client.Close())
	waitSIP(t, hp, done)
	require.Zero(t, sipRecall.Counter("sip", net.ParseIP("212.129.10.158"), sipproto.UnackedCounter))
}

func TestHandleSIPTCPAckTimeoutHangsUp(t *testing.T) {
	for _, tc := range []struct {
		name      string
		md        connection.Metadata
		transport string
	}{
		{"tcp", connection.Metadata{}, "TCP"},
		{"tls", connection.Metadata{TLS: &connection.TLSInfo{}}, "TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timers := stubSIPTimers(t)
			stubSIPRecall(t)
			remote := staticAddr{"212.129.10.158:65145"}
			client, hp, done := startSIPWith(t, remote, tc.md)

			_, err := client.Write(sipInviteRead1)
			require.NoError(t, err)
			requireStatus(t, readSIPReply(t, client), "100")
			requireStatus(t, readSIPReply(t, client), "180")
			timers.fire(t, sipRing)
			requireStatus(t, readSIPReply(t, client), "200")

			timers.fire(t, sipTCPAckTimeout)
			bye := readSIPReply(t, client)
			require.True(t, strings.HasPrefix(bye, "BYE sip:14500163172166221:5060@212.129.10.158:65145 SIP/2.0\r\n"), bye)
			require.Contains(t, bye, "Via: SIP/2.0/"+tc.transport+" ")
			require.Contains(t, bye, `Reason: SIP ;cause=408 ;text="Request Timeout"`)
			require.Equal(t, 1, sipRecall.Counter("sip", net.ParseIP("212.129.10.158"), sipproto.UnackedCounter))

			// the connection stays open; the next call escalates to progress
			_, err = client.Write(sipInviteFor("call-2"))
			require.NoError(t, err)
			requireStatus(t, readSIPReply(t, client), "100")
			requireStatus(t, readSIPReply(t, client), "183")
			require.NoError(t, client.Close())

			produced := waitSIP(t, hp, done)
			events := produced.decoded.([]parsedSIP)
			require.Equal(t, []string{"<INVITE", "100", "180", "200", "BYE", "<INVITE", "100", "183"}, statuses(events))
			require.Equal(t, "answer", events[4].Variant, "the BYE belongs to the answered call")
			require.Equal(t, "progress", events[6].Variant)
			require.Equal(t, connection.EndClientClose, produced.endReason)
		})
	}
}

// startSIPVisit runs the handler for a source on its nth visit.
func startSIPVisit(t *testing.T, n int) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	advance := stubSIPRecall(t)
	remote := staticAddr{"212.129.10.158:65145"}
	for i := 1; i < n; i++ {
		sipRecall.Begin("sip", net.ParseIP("212.129.10.158"), len(sipproto.Variants))
		advance(time.Hour)
	}
	return startSIPFrom(t, remote)
}

func TestHandleSIPTCPVariants(t *testing.T) {
	t.Run("progress", func(t *testing.T) {
		timers := stubSIPTimers(t)
		client, hp, done := startSIPVisit(t, 2)
		_, err := client.Write(sipInviteRead1)
		require.NoError(t, err)
		requireStatus(t, readSIPReply(t, client), "100")
		progress := readSIPReply(t, client)
		requireStatus(t, progress, "183")
		require.Contains(t, progress, "Content-Type: application/sdp\r\n")
		timers.fire(t, sipRing)
		requireStatus(t, readSIPReply(t, client), "200")
		require.NoError(t, client.Close())
		events := waitSIP(t, hp, done).decoded.([]parsedSIP)
		require.Equal(t, "progress", events[1].Variant)
	})

	t.Run("auth", func(t *testing.T) {
		timers := stubSIPTimers(t)
		client, hp, done := startSIPVisit(t, 3)
		_, err := client.Write(sipInviteRead1)
		require.NoError(t, err)
		requireStatus(t, readSIPReply(t, client), "401")
		_, err = client.Write(sipInDialog("ACK", 1, "1492163839-465544234-336545636"))
		require.NoError(t, err)
		authed := strings.Replace(string(sipInviteRead1), "CSeq: 1 INVITE", "CSeq: 2 INVITE", 1)
		authed = strings.Replace(authed, "User-Agent: pplsip\r\n", "User-Agent: pplsip\r\nAuthorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"feedface\", uri=\"sip:14500972598112101@1.2.3.4\", response=\"00\"\r\n", 1)
		_, err = client.Write([]byte(authed))
		require.NoError(t, err)
		requireStatus(t, readSIPReply(t, client), "100")
		requireStatus(t, readSIPReply(t, client), "180")
		timers.fire(t, sipRing)
		requireStatus(t, readSIPReply(t, client), "200")
		require.NoError(t, client.Close())
		events := waitSIP(t, hp, done).decoded.([]parsedSIP)
		require.Equal(t, []string{"<INVITE", "401", "<ACK", "<INVITE", "100", "180", "200"}, statuses(events))
		require.Equal(t, "100", events[3].Username)
	})

	t.Run("busy", func(t *testing.T) {
		timers := stubSIPTimers(t)
		client, hp, done := startSIPVisit(t, 4)
		_, err := client.Write(sipInviteRead1)
		require.NoError(t, err)
		requireStatus(t, readSIPReply(t, client), "100")
		requireStatus(t, readSIPReply(t, client), "180")
		timers.fire(t, sipRing)
		busy := readSIPReply(t, client)
		requireStatus(t, busy, "486")
		require.Contains(t, busy, ";tag=feedface\r\n")
		require.NoError(t, client.Close())
		events := waitSIP(t, hp, done).decoded.([]parsedSIP)
		require.Equal(t, "busy", events[1].Variant)
	})
}

func TestHandleSIPTCPRetransmittedInvite(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	_, err := client.Write(sipInviteRead1)
	require.NoError(t, err)
	requireStatus(t, readSIPReply(t, client), "100")
	ringing := readSIPReply(t, client)
	_, err = client.Write(sipInviteRead1)
	require.NoError(t, err)
	require.Equal(t, ringing, readSIPReply(t, client), "the retransmit gets the latest response")
	require.NoError(t, client.Close())
	events := waitSIP(t, hp, done).decoded.([]parsedSIP)
	require.Equal(t, []string{"<INVITE", "100", "180", "<INVITE", "180"}, statuses(events))
}

func TestHandleSIPTCPFrameCap(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	for i := 0; i < maxSIPTCPFrames/2; i++ {
		_, err := client.Write(sipOptionsRead)
		require.NoError(t, err)
		requireStatus(t, readSIPReply(t, client), "200")
	}
	produced := waitSIP(t, hp, done)
	require.Len(t, produced.decoded, maxSIPTCPFrames)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
}

func TestHandleSIPTCPTruncatedBody(t *testing.T) {
	stubSIPTimers(t)
	client, hp, done := startSIP(t)
	big := "MESSAGE sip:100@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 5.6.7.8:5060;branch=z9hG4bK-m\r\nFrom: <sip:100@1.2.3.4>;tag=m1\r\nTo: <sip:100@1.2.3.4>\r\nCall-ID: m-1\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nContent-Length: 5000\r\n\r\n" + strings.Repeat("x", 5000)
	go func() { _, _ = client.Write(append([]byte(big), sipOptionsRead...)) }()
	// the truncated MESSAGE may or may not parse; the OPTIONS after it is
	// framed correctly either way
	var opt string
	for {
		opt = readSIPReply(t, client)
		if strings.Contains(opt, "CSeq: 1 OPTIONS") {
			break
		}
	}
	requireStatus(t, opt, "200")
	require.NoError(t, client.Close())
	events := waitSIP(t, hp, done).decoded.([]parsedSIP)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, len(big)-5000+sipMaxBody)
	require.Equal(t, "OPTIONS", events[len(events)-2].Command)
}
