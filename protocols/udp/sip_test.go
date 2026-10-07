package udp

import (
	"context"
	"encoding/json"
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

type producedUDP struct {
	handler   string
	payload   []byte
	decoded   interface{}
	endReason string
}

type recordingHoneypot struct {
	mu       sync.Mutex
	produced []producedUDP
	replies  [][]byte
}

func (h *recordingHoneypot) ProduceTCP(string, net.Conn, connection.Metadata, []byte, interface{}) error {
	return nil
}

func (h *recordingHoneypot) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.produced = append(h.produced, producedUDP{handler: handler, payload: append([]byte(nil), payload...), decoded: decoded, endReason: md.EndReason})
	return nil
}

func (h *recordingHoneypot) ReplyUDP(srcAddr, dstAddr *net.UDPAddr, payload []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.replies = append(h.replies, append([]byte(nil), payload...))
	return nil
}

func (h *recordingHoneypot) ConnectionByFlow([2]uint64) connection.Metadata {
	return connection.Metadata{}
}
func (h *recordingHoneypot) UpdateConnectionTimeout(context.Context, net.Conn) error {
	return nil
}
func (h *recordingHoneypot) MetadataByConnection(net.Conn) (connection.Metadata, error) {
	return connection.Metadata{}, nil
}

type testLogger struct{}

func (testLogger) Debug(string, ...any) {}
func (testLogger) Info(string, ...any)  {}
func (testLogger) Warn(string, ...any)  {}
func (testLogger) Error(string, ...any) {}

func sipOptions() []byte {
	return []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: \"sipvicious\"<sip:100@1.1.1.1>\r\n" +
		"From: \"sipvicious\"<sip:100@1.1.1.1>;tag=abc\r\n" +
		"User-Agent: friendly-scanner\r\n" +
		"Call-ID: 12345\r\n" +
		"Contact: sip:100@203.0.113.10:5079\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Accept: application/sdp\r\n" +
		"Content-Length: 0\r\n\r\n")
}

func TestHandleSIPOptions(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, sipOptions(), connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)

	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.True(t, strings.HasPrefix(string(h.produced[0].payload), "OPTIONS "))

	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "OPTIONS", events[0].Command)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
	require.Contains(t, string(events[1].Payload), "SIP/2.0 200")
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	require.Len(t, h.replies, 1)
	require.Contains(t, string(h.replies[0]), "SIP/2.0 200")
}

// read frame 1 of Ochi event f06fe1f1-27fc-4f49-8d2d-77d2f31fdf1f ("VOIP" extension scanner)
var voipRegisterRead1 = []byte("REGISTER sip:1.2.3.4:5060 SIP/2.0\r\n" +
	"To: <sip:100@1.2.3.4>\r\n" +
	"From: <sip:100@1.2.3.4>;tag=e5f4a9860666e4f7a\r\n" +
	"Via: SIP/2.0/UDP 185.243.5.243:49618;branch=z9hG4bK-d87543-987333414-1--d87543-;rport\r\n" +
	"Call-ID: e5f4a986066756e4f7a\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"Contact: <sip:100@185.243.5.243:49618>\r\n" +
	"Expires: 3600\r\n" +
	"Max-Forwards: 70\r\n" +
	"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n" +
	"User-Agent: VOIP\r\n" +
	"Content-Length: 0\r\n\r\n")

func TestHandleSIPRegisterAccepted(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("185.243.5.243"), Port: 49618}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, voipRegisterRead1, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)

	// rport requested: filled with the source port, and received added (RFC 3581)
	wantReply := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 185.243.5.243:49618;branch=z9hG4bK-d87543-987333414-1--d87543-;rport=49618;received=185.243.5.243\r\n" +
		"From: <sip:100@1.2.3.4>;tag=e5f4a9860666e4f7a\r\n" +
		"To: <sip:100@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: e5f4a986066756e4f7a\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n" +
		"Contact: <sip:100@185.243.5.243:49618>;expires=3600\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	require.Equal(t, [][]byte{[]byte(wantReply)}, h.replies)

	require.Len(t, h.produced, 1)
	require.Equal(t, []parsedSIP{
		{
			Direction: "read",
			Command:   "REGISTER",
			Path:      "sip:1.2.3.4:5060",
			From:      "sip:100@1.2.3.4",
			To:        "sip:100@1.2.3.4",
			CallID:    "e5f4a986066756e4f7a",
			UserAgent: "VOIP",
			Payload:   voipRegisterRead1,
		},
		{
			Direction: "write",
			Variant:   "answer",
			Visit:     1,
			Status:    "200",
			From:      "sip:100@1.2.3.4",
			To:        "sip:100@1.2.3.4",
			CallID:    "e5f4a986066756e4f7a",
			UserAgent: "Asterisk PBX 18.20.0",
			Payload:   []byte(wantReply),
		},
	}, h.produced[0].decoded)
}

// read frame 1 of Ochi event 748a8b05-6a95-4592-94b5-15cb4ea65164 (pplsip toll-fraud INVITE)
var pplsipInviteRead1 = []byte("INVITE sip:14500972598112101@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\nMax-Forwards: 70\r\nFrom: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\nTo: <sip:14500972598112101@1.2.3.4>\r\nCall-ID: 1492163839-465544234-336545636\r\nCSeq: 1 INVITE\r\nContact: <sip:14500163172166221:5060@212.129.10.158:65145>\r\nUser-Agent: pplsip\r\nContent-Type: application/sdp\r\nContent-Length: 211\r\n\r\nv=0\r\no=14500163172166221:5060 16264 18299 IN IP4 0.0.0.0\r\ns=pplsip\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 25282 RTP/AVP 100 6 0 8 3 18 5 101\r\na=rtpmap:0 pcmu/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\n")

func stubSIPResponder(t *testing.T) {
	t.Helper()
	orig := sipResponder
	sipResponder = &sipproto.Responder{Token: func() string { return "feedface" }}
	t.Cleanup(func() { sipResponder = orig })
	stubSIPRecall(t)
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

func TestHandleSIPInviteAnswered(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, pplsipInviteRead1, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	// the INVITE opens a dialog: nothing is produced until it ends
	require.Empty(t, h.produced)
	// 100 and 180 go out at once, the 200 OK only after ringing
	require.Len(t, h.replies, 2)
	timers.fire(t, sipRing)
	require.Len(t, h.replies, 3)
	timers.fire(t, time.Minute)

	// sent-by 0.0.0.0 is not the packet source: received is added (RFC 3261 §18.2.1)
	dialog := "Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159;received=51.75.106.116\r\n" +
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n"
	tail := "Call-ID: 1492163839-465544234-336545636\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n"
	contact := "Contact: <sip:14500972598112101@1.2.3.4:5060>\r\n"
	trying := "SIP/2.0 100 Trying\r\n" + dialog +
		"To: <sip:14500972598112101@1.2.3.4>\r\n" + tail +
		"Content-Length: 0\r\n\r\n"
	ringing := "SIP/2.0 180 Ringing\r\n" + dialog +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" + tail + contact +
		"Content-Length: 0\r\n\r\n"
	sdp := "v=0\r\n" +
		"o=- 9102 9104 IN IP4 1.2.3.4\r\n" +
		"s=Asterisk\r\n" +
		"c=IN IP4 1.2.3.4\r\n" +
		"t=0 0\r\n" +
		"m=audio 18204 RTP/AVP 0 101\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-16\r\n" +
		"a=ptime:20\r\n" +
		"a=maxptime:150\r\n" +
		"a=sendrecv\r\n"
	ok := "SIP/2.0 200 OK\r\n" + dialog +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" + tail + contact +
		"Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER\r\n" +
		"Supported: 100rel, timer, replaces, norefersub\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(sdp)) + "\r\n\r\n" + sdp
	require.Equal(t, []string{trying, ringing, ok}, replyStrings(h.replies))

	require.Len(t, h.produced, 1)
	require.Equal(t, pplsipInviteRead1, h.produced[0].payload)
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	write := func(status, payload string) parsedSIP {
		return parsedSIP{
			Direction: "write",
			Variant:   "answer",
			Visit:     1,
			Status:    status,
			From:      "sip:14500163172166221:5060@1.2.3.4",
			To:        "sip:14500972598112101@1.2.3.4",
			CallID:    "1492163839-465544234-336545636",
			UserAgent: "Asterisk PBX 18.20.0",
			Payload:   []byte(payload),
		}
	}
	require.Equal(t, []parsedSIP{
		{
			Direction: "read",
			Command:   "INVITE",
			Path:      "sip:14500972598112101@1.2.3.4",
			From:      "sip:14500163172166221:5060@1.2.3.4",
			To:        "sip:14500972598112101@1.2.3.4",
			CallID:    "1492163839-465544234-336545636",
			UserAgent: "pplsip",
			Payload:   pplsipInviteRead1,
		},
		write("100", trying),
		write("180", ringing),
		write("200", ok),
	}, h.produced[0].decoded)
}

func replyStrings(replies [][]byte) []string {
	out := make([]string, len(replies))
	for i, r := range replies {
		out[i] = string(r)
	}
	return out
}

func TestHandleSIPRegisterWithCredentialsAccepted(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("185.243.5.243"), Port: 49618}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}
	digest := `Authorization: Digest username="100",realm="asterisk",nonce="feedface",uri="sip:1.2.3.4:5060",response="d41d8cd98f00b204e9800998ecf8427e"`
	req := []byte(strings.Replace(string(voipRegisterRead1), "User-Agent: VOIP\r\n", "User-Agent: VOIP\r\n"+digest+"\r\n", 1))

	err := HandleSIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.replies, 1)
	require.True(t, strings.HasPrefix(string(h.replies[0]), "SIP/2.0 200 OK\r\n"))

	events := h.produced[0].decoded.([]parsedSIP)
	require.Len(t, events, 2)
	require.Equal(t, "100", events[0].Username)
	require.Equal(t, "200", events[1].Status)
	// only the username is lifted into decoded; the digest response stays in the raw payload
	decoded, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(decoded), "d41d8cd98f00b204e9800998ecf8427e")
}

func TestHandleSIPAckNoReply(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}
	ack := []byte("ACK sip:14500972598112101@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n" +
		"From: <sip:1450@1.2.3.4>;tag=414451770\r\n" +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: 1492163839-465544234-336545636\r\n" +
		"CSeq: 1 ACK\r\n" +
		"Content-Length: 0\r\n\r\n")

	err := HandleSIP(context.Background(), src, dst, ack, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedSIP)
	require.Len(t, events, 1)
	require.Equal(t, "ACK", events[0].Command)
}

func TestHandleSIPOversizeTruncated(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}
	data := append([]byte("INVITE sip:1@1.2.3.4 SIP/2.0\r\nX-Pad: "), []byte(strings.Repeat("A", maxSIPPayload))...)

	_ = HandleSIP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h)
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedSIP)
	require.Len(t, events, 1)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxSIPPayload)
}

func TestHandleSIPMalformedStillProduces(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, []byte("not-sip"), connection.Metadata{}, testLogger{}, h)
	require.Error(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, []byte("not-sip"), events[0].Payload)
}

func TestHandleSIPEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
}

type fakeSIPTimer struct {
	d       time.Duration
	f       func()
	stopped bool
	fired   bool
}

func (ft *fakeSIPTimer) Stop() bool {
	ft.stopped = true
	return !ft.fired
}

// fakeSIPTimers records dialog timers; tests fire them by hand.
type fakeSIPTimers struct {
	mu     sync.Mutex
	timers []*fakeSIPTimer
}

func (ts *fakeSIPTimers) afterFunc(d time.Duration, f func()) sipTimer {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ft := &fakeSIPTimer{d: d, f: f}
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

// fire runs the oldest armed timer of duration d.
func (ts *fakeSIPTimers) fire(t *testing.T, d time.Duration) {
	t.Helper()
	ts.mu.Lock()
	var target *fakeSIPTimer
	for _, ft := range ts.timers {
		if !ft.stopped && !ft.fired && ft.d == d {
			target = ft
			break
		}
	}
	require.NotNil(t, target, "no armed %v timer", d)
	target.fired = true
	ts.mu.Unlock()
	target.f()
}

// sipRing is the ringing delay in tests.
const sipRing = 3 * time.Second

// stubSIPDialogs gives the test a fresh dialog table and hand-fired timers;
// the idle timeout is one minute, INVITEs ring for sipRing and none are
// rejected.
func stubSIPDialogs(t *testing.T) *fakeSIPTimers {
	t.Helper()
	timers := &fakeSIPTimers{}
	origTable, origAfter, origIdle := sipDialogs, sipAfterFunc, sipIdle
	origLimit, origRing := sipRejectLimit, sipRingDelay
	sipDialogs = newSIPDialogTable(maxSIPDialogs)
	sipAfterFunc = timers.afterFunc
	sipIdle = time.Minute
	sipRejectLimit = 0
	sipRingDelay = func() time.Duration { return sipRing }
	t.Cleanup(func() {
		sipDialogs, sipAfterFunc, sipIdle = origTable, origAfter, origIdle
		sipRejectLimit, sipRingDelay = origLimit, origRing
	})
	return timers
}

const pplsipCallID = "1492163839-465544234-336545636"

// pplsipInDialog builds an in-dialog request of the pplsip call.
func pplsipInDialog(method string, seq int, callID string) []byte {
	return []byte(method + " sip:14500972598112101@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK-" + strings.ToLower(method) + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + strconv.Itoa(seq) + " " + method + "\r\n" +
		"User-Agent: pplsip\r\n" +
		"Content-Length: 0\r\n\r\n")
}

func inviteWithCallID(callID string) []byte {
	return []byte(strings.Replace(string(pplsipInviteRead1), pplsipCallID, callID, 1))
}

type sipFrameSummary struct {
	direction, command, status, callID string
	payload                            string
}

func summarizeSIP(t *testing.T, decoded interface{}) []sipFrameSummary {
	t.Helper()
	events, ok := decoded.([]parsedSIP)
	require.True(t, ok)
	out := make([]sipFrameSummary, len(events))
	for i, e := range events {
		out[i] = sipFrameSummary{e.Direction, e.Command, e.Status, e.CallID, string(e.Payload)}
	}
	return out
}

var (
	pplsipSrc = &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	pplsipDst = &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}
)

func sendSIP(t *testing.T, h *recordingHoneypot, src *net.UDPAddr, data []byte) {
	t.Helper()
	require.NoError(t, HandleSIP(context.Background(), src, pplsipDst, data, connection.Metadata{}, testLogger{}, h))
}

func TestHandleSIPDialogInviteAckBye(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}
	ack := pplsipInDialog("ACK", 1, pplsipCallID)
	bye := pplsipInDialog("BYE", 2, pplsipCallID)

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.Len(t, h.replies, 2)
	require.Equal(t, []time.Duration{time.Minute, sipRing}, timers.pending())
	timers.fire(t, sipRing)
	require.Len(t, h.replies, 3)
	require.Empty(t, h.produced)
	require.Equal(t, []time.Duration{time.Minute, sipT1}, timers.pending())

	sendSIP(t, h, pplsipSrc, ack)
	require.Len(t, h.replies, 3)
	require.Empty(t, h.produced)
	// the ACK stops the 200 OK resends
	require.Equal(t, []time.Duration{time.Minute}, timers.pending())

	sendSIP(t, h, pplsipSrc, bye)
	require.Len(t, h.replies, 4)
	require.True(t, strings.HasPrefix(string(h.replies[3]), "SIP/2.0 200 OK\r\n"))
	require.Empty(t, timers.pending())

	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	require.Equal(t, pplsipInviteRead1, h.produced[0].payload)
	r := replyStrings(h.replies)
	require.Equal(t, []sipFrameSummary{
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "100", pplsipCallID, r[0]},
		{"write", "", "180", pplsipCallID, r[1]},
		{"write", "", "200", pplsipCallID, r[2]},
		{"read", "ACK", "", pplsipCallID, string(ack)},
		{"read", "BYE", "", pplsipCallID, string(bye)},
		{"write", "", "200", pplsipCallID, r[3]},
	}, summarizeSIP(t, h.produced[0].decoded))

	// a BYE retransmitted after the dialog ended is an event of its own
	sendSIP(t, h, pplsipSrc, bye)
	require.Len(t, h.produced, 2)
	require.Len(t, summarizeSIP(t, h.produced[1].decoded), 2)
}

func TestHandleSIPDialogIdleTimeoutResendsOK(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	timers.fire(t, sipRing)
	ok := h.replies[2]

	// T1 doubling up to T2 until 64*T1 has passed (RFC 3261 §13.3.1.4)
	schedule := []time.Duration{sipT1, 2 * sipT1, 4 * sipT1, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2}
	for i, d := range schedule {
		timers.fire(t, d)
		require.Len(t, h.replies, 4+i, "resend %d", i)
		require.Equal(t, ok, h.replies[3+i])
	}
	// the next firing passes 64*T1: hang up with a BYE like Asterisk/pjsip
	// and produce right away instead of waiting for the idle timeout
	timers.fire(t, sipT2)
	wantBye := "BYE sip:14500163172166221:5060@212.129.10.158:65145 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 1.2.3.4:5060;rport;branch=z9hG4bKPjfeedface\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"To: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
		"Call-ID: " + pplsipCallID + "\r\n" +
		"CSeq: 63933 BYE\r\n" +
		`Reason: SIP ;cause=408 ;text="Request Timeout"` + "\r\n" +
		"User-Agent: Asterisk PBX 18.20.0\r\n" +
		"Content-Length: 0\r\n\r\n"
	require.Len(t, h.replies, 4+len(schedule))
	require.Equal(t, wantBye, string(h.replies[3+len(schedule)]))
	require.Empty(t, timers.pending())

	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	frames := summarizeSIP(t, h.produced[0].decoded)
	require.Len(t, frames, 1+3+len(schedule)+1)
	require.Equal(t, "INVITE", frames[0].command)
	for _, f := range frames[4 : 4+len(schedule)] {
		require.Equal(t, sipFrameSummary{"write", "", "200", pplsipCallID, string(ok)}, f)
	}
	require.Equal(t, sipFrameSummary{"write", "BYE", "", pplsipCallID, wantBye}, frames[len(frames)-1])
	require.Empty(t, sipDialogs.dialogs)

	// the caller's 200 OK to our BYE lands after the dialog is gone: it is
	// a standalone event and gets no reply
	byeOK := []byte("SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 1.2.3.4:5060;rport;branch=z9hG4bKPjfeedface\r\n" +
		"From: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"To: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
		"Call-ID: " + pplsipCallID + "\r\n" +
		"CSeq: 63933 BYE\r\n" +
		"Content-Length: 0\r\n\r\n")
	sendSIP(t, h, pplsipSrc, byeOK)
	require.Len(t, h.produced, 2)
	require.Len(t, h.replies, 4+len(schedule))
	require.Equal(t, []sipFrameSummary{{"read", "", "200", pplsipCallID, string(byeOK)}}, summarizeSIP(t, h.produced[1].decoded))
}

func TestHandleSIPDialogAckPreventsBye(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	timers.fire(t, sipRing)
	timers.fire(t, sipT1)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("ACK", 1, pplsipCallID))
	// no resend timer left to reach 64*T1, so no BYE
	require.Equal(t, []time.Duration{time.Minute}, timers.pending())

	timers.fire(t, time.Minute)
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	for _, r := range h.replies {
		require.False(t, strings.HasPrefix(string(r), "BYE "))
	}
	require.Len(t, h.replies, 4)
}

func TestHandleSIPDialogInviteRetransmitReplaysOK(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	// while ringing, a retransmit gets the 180 again
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.Len(t, h.replies, 3)
	require.Equal(t, h.replies[1], h.replies[2])
	timers.fire(t, sipRing)
	// once answered, the same 200 OK (same To tag and SDP), not a second 100/180/200
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.Len(t, h.replies, 5)
	require.Equal(t, h.replies[3], h.replies[4])

	timers.fire(t, time.Minute)
	require.Len(t, h.produced, 1)
	r := replyStrings(h.replies)
	require.Equal(t, []sipFrameSummary{
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "100", pplsipCallID, r[0]},
		{"write", "", "180", pplsipCallID, r[1]},
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "180", pplsipCallID, r[2]},
		{"write", "", "200", pplsipCallID, r[3]},
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "200", pplsipCallID, r[4]},
	}, summarizeSIP(t, h.produced[0].decoded))
}

func TestHandleSIPDialogsStaySeparate(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 65145}

	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-a"))
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-b"))
	// same Call-ID from another source is another dialog
	sendSIP(t, h, other, inviteWithCallID("call-a"))
	for range 3 {
		timers.fire(t, sipRing)
	}
	require.Empty(t, h.produced)

	sendSIP(t, h, pplsipSrc, pplsipInDialog("BYE", 2, "call-a"))
	require.Len(t, h.produced, 1)
	sendSIP(t, h, other, pplsipInDialog("BYE", 2, "call-a"))
	require.Len(t, h.produced, 2)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("BYE", 2, "call-b"))
	require.Len(t, h.produced, 3)

	for i, callID := range []string{"call-a", "call-a", "call-b"} {
		frames := summarizeSIP(t, h.produced[i].decoded)
		require.Len(t, frames, 6, "event %d", i)
		for _, f := range frames {
			require.Equal(t, callID, f.callID, "event %d", i)
		}
		require.Equal(t, connection.EndClientClose, h.produced[i].endReason)
	}
}

func TestHandleSIPDialogCancelWhileRinging(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}
	cancel := pplsipInDialog("CANCEL", 1, pplsipCallID)
	ack := pplsipInDialog("ACK", 1, pplsipCallID)

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	sendSIP(t, h, pplsipSrc, cancel)
	// 200 OK to the CANCEL, then 487 to the INVITE; the 200 OK to the
	// INVITE is never sent
	require.Equal(t, []time.Duration{time.Minute, sipT1}, timers.pending())
	r := replyStrings(h.replies)
	require.Len(t, r, 4)
	require.True(t, strings.HasPrefix(r[2], "SIP/2.0 200 OK\r\n"))
	require.Contains(t, r[2], "CSeq: 1 CANCEL\r\n")
	// both share the 180's To tag (RFC 3261 §9.2)
	want487 := "SIP/2.0 487 Request Terminated\r\n" +
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159;received=51.75.106.116\r\n" +
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: " + pplsipCallID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n" +
		"Content-Length: 0\r\n\r\n"
	require.Equal(t, want487, r[3])
	require.Empty(t, h.produced)

	// a retransmitted INVITE now gets the 487
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.Equal(t, want487, string(h.replies[4]))

	sendSIP(t, h, pplsipSrc, ack)
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	require.Empty(t, timers.pending())
	require.Equal(t, []sipFrameSummary{
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "100", pplsipCallID, r[0]},
		{"write", "", "180", pplsipCallID, r[1]},
		{"read", "CANCEL", "", pplsipCallID, string(cancel)},
		{"write", "", "200", pplsipCallID, r[2]},
		{"write", "", "487", pplsipCallID, want487},
		{"read", "INVITE", "", pplsipCallID, string(pplsipInviteRead1)},
		{"write", "", "487", pplsipCallID, want487},
		{"read", "ACK", "", pplsipCallID, string(ack)},
	}, summarizeSIP(t, h.produced[0].decoded))
}

func TestHandleSIPDialogCancelUnacked(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("CANCEL", 1, pplsipCallID))
	for _, d := range []time.Duration{sipT1, 2 * sipT1, 4 * sipT1, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2} {
		timers.fire(t, d)
	}
	// the 487 is resent like the 200 OK, but Timer H ends it without a BYE;
	// the caller hung up, so it is still client_close
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	for _, r := range h.replies {
		require.False(t, strings.HasPrefix(string(r), "BYE "))
	}
	require.Len(t, h.replies, 4+10)
}

// CANCEL after the call was answered matches no pending INVITE
func TestHandleSIPDialogCancelAfterAnswer(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	timers.fire(t, sipRing)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("CANCEL", 1, pplsipCallID))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	frames := summarizeSIP(t, h.produced[0].decoded)
	require.Len(t, frames, 6)
	require.Equal(t, "CANCEL", frames[4].command)
	require.Equal(t, "481", frames[5].status)
	require.Empty(t, timers.pending())
}

func TestHandleSIPInviteRejected(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	sipRejectLimit = 2
	advance := stubSIPRecall(t)
	h := &recordingHoneypot{}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 65145}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	want404 := "SIP/2.0 404 Not Found\r\n" +
		"Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159;received=51.75.106.116\r\n" +
		"From: <sip:14500163172166221:5060@1.2.3.4>;tag=414451770\r\n" +
		"To: <sip:14500972598112101@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: " + pplsipCallID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n" +
		"Content-Length: 0\r\n\r\n"
	r := replyStrings(h.replies)
	require.Len(t, r, 2)
	require.True(t, strings.HasPrefix(r[0], "SIP/2.0 100 Trying\r\n"))
	require.Equal(t, want404, r[1])
	// no ringing; the 404 is resent until ACKed
	require.Equal(t, []time.Duration{time.Minute, sipT1}, timers.pending())
	timers.fire(t, sipT1)
	require.Equal(t, want404, string(h.replies[2]))

	// the ACK to a non-2xx final reuses the INVITE branch (RFC 3261 §17.1.1.3)
	ack := []byte(strings.Replace(string(pplsipInDialog("ACK", 1, pplsipCallID)), "branch=z9hG4bK-ack", "branch=z9hG4bK951917159", 1))
	sendSIP(t, h, pplsipSrc, ack)
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	require.Equal(t, pplsipInviteRead1, h.produced[0].payload)
	require.Empty(t, timers.pending())
	require.Equal(t, []parsedSIP{
		{
			Direction: "read",
			Command:   "INVITE",
			Path:      "sip:14500972598112101@1.2.3.4",
			From:      "sip:14500163172166221:5060@1.2.3.4",
			To:        "sip:14500972598112101@1.2.3.4",
			CallID:    pplsipCallID,
			UserAgent: "pplsip",
			Payload:   pplsipInviteRead1,
		},
		{Direction: "write", Variant: "answer", Visit: 1, Status: "100", From: "sip:14500163172166221:5060@1.2.3.4", To: "sip:14500972598112101@1.2.3.4", CallID: pplsipCallID, UserAgent: "Asterisk PBX 18.20.0", Payload: []byte(r[0])},
		{Direction: "write", Variant: "answer", Visit: 1, Status: "404", From: "sip:14500163172166221:5060@1.2.3.4", To: "sip:14500972598112101@1.2.3.4", CallID: pplsipCallID, UserAgent: "Asterisk PBX 18.20.0", Payload: []byte(want404)},
		{Direction: "write", Variant: "answer", Visit: 1, Status: "404", From: "sip:14500163172166221:5060@1.2.3.4", To: "sip:14500972598112101@1.2.3.4", CallID: pplsipCallID, UserAgent: "Asterisk PBX 18.20.0", Payload: []byte(want404)},
		{
			Direction: "read",
			Command:   "ACK",
			Path:      "sip:14500972598112101@1.2.3.4",
			From:      "sip:14500163172166221:5060@1.2.3.4",
			To:        "sip:14500972598112101@1.2.3.4",
			CallID:    pplsipCallID,
			UserAgent: "pplsip",
			Payload:   ack,
		},
	}, h.produced[0].decoded)

	// the next prefix is rejected too, each call its own event
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-2"))
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 404 Not Found\r\n"))
	// the third rings, and a retransmit of the rejected INVITE does not
	// count as a new call
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-2"))
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-3"))
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 180 Ringing\r\n"))
	// another source starts its own count
	sendSIP(t, h, other, inviteWithCallID("call-4"))
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 404 Not Found\r\n"))
	// activity inside the visit gap keeps the count
	advance(59 * time.Minute)
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-5"))
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 180 Ringing\r\n"))
	// a new visit starts the count over, before its variant applies
	advance(time.Hour)
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-6"))
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 404 Not Found\r\n"))
}

func TestHandleSIPInviteRejectNeedsRecall(t *testing.T) {
	stubSIPResponder(t)
	stubSIPDialogs(t)
	sipRejectLimit = 2
	sipRecall = recall.New(recall.Config{Enabled: false})
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 180 Ringing\r\n"))
}

func TestHandleSIPInviteRejectedUnacked(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	sipRejectLimit = 1
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	schedule := []time.Duration{sipT1, 2 * sipT1, 4 * sipT1, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2}
	for _, d := range schedule {
		timers.fire(t, d)
	}
	require.Empty(t, h.produced)
	// Timer H: give up on the ACK without a BYE (there is no call to hang up)
	timers.fire(t, sipT2)
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	require.Len(t, h.replies, 2+len(schedule))
	for _, r := range h.replies[1:] {
		require.True(t, strings.HasPrefix(string(r), "SIP/2.0 404 Not Found\r\n"))
	}
	require.Empty(t, timers.pending())
}

func TestHandleSIPDialogEviction(t *testing.T) {
	stubSIPResponder(t)
	stubSIPDialogs(t)
	sipDialogs = newSIPDialogTable(2)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-a"))
	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-b"))
	// activity on call-a makes call-b the least recently active
	sendSIP(t, h, pplsipSrc, pplsipInDialog("ACK", 1, "call-a"))
	require.Empty(t, h.produced)

	sendSIP(t, h, pplsipSrc, inviteWithCallID("call-c"))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndEvicted, h.produced[0].endReason)
	require.Equal(t, "call-b", summarizeSIP(t, h.produced[0].decoded)[0].callID)
	require.Len(t, sipDialogs.dialogs, 2)
}

func TestHandleSIPDialogMaxFrames(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	timers.fire(t, sipRing)
	for seq := 2; len(h.produced) == 0; seq++ {
		require.Less(t, seq, maxSIPDialogFrames, "dialog never hit the frame cap")
		sendSIP(t, h, pplsipSrc, pplsipInDialog("OPTIONS", seq, pplsipCallID))
	}
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndMaxFrames, h.produced[0].endReason)
	require.Len(t, summarizeSIP(t, h.produced[0].decoded), maxSIPDialogFrames)
	require.Empty(t, sipDialogs.dialogs)
}

func TestHandleSIPDialogFlushedOnShutdown(t *testing.T) {
	stubSIPResponder(t)
	stubSIPDialogs(t)
	h := &recordingHoneypot{}
	ctx, cancel := context.WithCancel(context.Background())

	require.NoError(t, HandleSIP(ctx, pplsipSrc, pplsipDst, pplsipInviteRead1, connection.Metadata{}, testLogger{}, h))
	cancel()
	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.produced) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
}

// read frame 1 of Ochi event a49a5a1a-059e-41b0-a803-b9bee477d99e: bare-LF
// lines and no empty line after the headers (extension 201 REGISTER probe)
var lfRegisterRead1 = []byte("REGISTER sip:201@1.2.3.4 SIP/2.0\n" +
	"To: 201 <sip:201@1.2.3.4>\n" +
	"From:  <sip:201@1.2.3.4>;tag=0c26cd11\n" +
	"Via: SIP/2.0/UDP 1.2.3.4:60090;branch=1vh0c2pqk11odh0s8omrmmzl8hp70xtr4st0n847ocn9bg3r854qnyscvg5ats7s4j6fvxg;rport\n" +
	"Call-ID: 1fae39cf1cb1c99e34205585834dbcba\n" +
	"CSeq: 1 REGISTER\n" +
	"Contact: <sip:201@1.2.3.4:60090>\n" +
	"User-Agent: \n" +
	"Max-forwards: 70\n" +
	"Allow: INVITE, ACK, CANCEL, BYE, REFER\n" +
	"Content-Type: application/sdp\n")

func TestHandleSIPRegisterBareLF(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("162.19.19.234"), Port: 60090}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}
	orig := string(lfRegisterRead1)

	err := HandleSIP(context.Background(), src, dst, lfRegisterRead1, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Equal(t, orig, string(lfRegisterRead1))

	// the reply is CRLF even though the request was not
	wantReply := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 1.2.3.4:60090;branch=1vh0c2pqk11odh0s8omrmmzl8hp70xtr4st0n847ocn9bg3r854qnyscvg5ats7s4j6fvxg;rport=60090;received=162.19.19.234\r\n" +
		"From: <sip:201@1.2.3.4>;tag=0c26cd11\r\n" +
		"To: \"201\" <sip:201@1.2.3.4>;tag=feedface\r\n" +
		"Call-ID: 1fae39cf1cb1c99e34205585834dbcba\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n" +
		"Contact: <sip:201@1.2.3.4:60090>;expires=3600\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	require.Equal(t, [][]byte{[]byte(wantReply)}, h.replies)

	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Equal(t, lfRegisterRead1, h.produced[0].payload)
	require.Equal(t, []parsedSIP{
		{
			Direction: "read",
			Command:   "REGISTER",
			Path:      "sip:201@1.2.3.4",
			From:      "sip:201@1.2.3.4",
			To:        "sip:201@1.2.3.4",
			CallID:    "1fae39cf1cb1c99e34205585834dbcba",
			Payload:   lfRegisterRead1, // raw wire bytes, not the normalized form
		},
		{
			Direction: "write",
			Variant:   "answer",
			Visit:     1,
			Status:    "200",
			From:      "sip:201@1.2.3.4",
			To:        "sip:201@1.2.3.4",
			CallID:    "1fae39cf1cb1c99e34205585834dbcba",
			UserAgent: "Asterisk PBX 18.20.0",
			Payload:   []byte(wantReply),
		},
	}, h.produced[0].decoded)
}

func TestHandleSIPDialogBareLF(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	h := &recordingHoneypot{}
	lf := func(data []byte) []byte {
		return []byte(strings.ReplaceAll(string(data), "\r\n", "\n"))
	}
	invite := lf(pplsipInviteRead1)
	ack := lf(pplsipInDialog("ACK", 1, pplsipCallID))
	bye := lf(pplsipInDialog("BYE", 2, pplsipCallID))

	sendSIP(t, h, pplsipSrc, invite)
	timers.fire(t, sipRing)
	require.Len(t, h.replies, 3)
	require.Empty(t, h.produced)
	sendSIP(t, h, pplsipSrc, ack)
	sendSIP(t, h, pplsipSrc, bye)
	require.Len(t, h.replies, 4)
	for _, r := range h.replies {
		require.NotContains(t, strings.ReplaceAll(string(r), "\r\n", ""), "\n", "reply must be CRLF: %q", r)
	}
	// the SDP answer is still built from the LF-only offer
	require.Contains(t, string(h.replies[2]), "m=audio ")

	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	r := replyStrings(h.replies)
	require.Equal(t, []sipFrameSummary{
		{"read", "INVITE", "", pplsipCallID, string(invite)},
		{"write", "", "100", pplsipCallID, r[0]},
		{"write", "", "180", pplsipCallID, r[1]},
		{"write", "", "200", pplsipCallID, r[2]},
		{"read", "ACK", "", pplsipCallID, string(ack)},
		{"read", "BYE", "", pplsipCallID, string(bye)},
		{"write", "", "200", pplsipCallID, r[3]},
	}, summarizeSIP(t, h.produced[0].decoded))
}

// writeVariants returns the variant and visit of each write frame.
func writeVariants(t *testing.T, decoded interface{}) []string {
	t.Helper()
	events, ok := decoded.([]parsedSIP)
	require.True(t, ok)
	var out []string
	for _, e := range events {
		if e.Direction == "write" {
			out = append(out, e.Variant+"/"+strconv.Itoa(e.Visit))
		}
	}
	return out
}

func statuses(frames []sipFrameSummary) []string {
	var out []string
	for _, f := range frames {
		if f.direction == "write" {
			out = append(out, f.status)
		}
	}
	return out
}

func TestHandleSIPReturningSourceRotatesVariants(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	advance := stubSIPRecall(t)
	h := &recordingHoneypot{}
	// the ACK to a non-2xx final reuses the INVITE branch (RFC 3261 §17.1.1.3)
	failedAck := []byte(strings.Replace(string(pplsipInDialog("ACK", 1, pplsipCallID)), "branch=z9hG4bK-ack", "branch=z9hG4bK951917159", 1))

	// visit 1: baseline, REGISTER accepted
	sendSIP(t, h, pplsipSrc, voipRegisterRead1)
	require.Len(t, h.produced, 1)
	require.Equal(t, []string{"200"}, statuses(summarizeSIP(t, h.produced[0].decoded)))
	require.Equal(t, []string{"answer/1"}, writeVariants(t, h.produced[0].decoded))

	// a REGISTER inside the gap stays in visit 1
	advance(30 * time.Minute)
	sendSIP(t, h, pplsipSrc, voipRegisterRead1)
	require.Equal(t, []string{"answer/1"}, writeVariants(t, h.produced[1].decoded))

	// visit 2: auth challenges REGISTER and INVITE until credentials arrive
	advance(time.Hour)
	sendSIP(t, h, pplsipSrc, voipRegisterRead1)
	require.Equal(t, []string{"401"}, statuses(summarizeSIP(t, h.produced[2].decoded)))
	require.Equal(t, []string{"auth/2"}, writeVariants(t, h.produced[2].decoded))

	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 401 Unauthorized\r\n"))
	sendSIP(t, h, pplsipSrc, failedAck)
	require.Len(t, h.produced, 3, "the ACK to a 401 keeps the dialog open for the authenticated retry")

	authed := strings.Replace(string(pplsipInviteRead1), "CSeq: 1 INVITE\r\n",
		"CSeq: 2 INVITE\r\nAuthorization: Digest username=\"1000\",realm=\"asterisk\",nonce=\"feedface\",uri=\"sip:14500972598112101@1.2.3.4\",response=\"00\"\r\n", 1)
	sendSIP(t, h, pplsipSrc, []byte(authed))
	timers.fire(t, sipRing)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("ACK", 2, pplsipCallID))
	sendSIP(t, h, pplsipSrc, pplsipInDialog("BYE", 3, pplsipCallID))
	require.Len(t, h.produced, 4)
	require.Equal(t, connection.EndClientClose, h.produced[3].endReason)
	frames := summarizeSIP(t, h.produced[3].decoded)
	require.Equal(t, []string{"401", "100", "180", "200", "200"}, statuses(frames))
	require.Equal(t, []string{"auth/2", "auth/2", "auth/2", "auth/2", "auth/2"}, writeVariants(t, h.produced[3].decoded))
	events := h.produced[3].decoded.([]parsedSIP)
	require.Equal(t, "INVITE", events[3].Command)
	require.Equal(t, "1000", events[3].Username)

	// visit 3: busy rings, then 486; its ACK ends the call
	advance(time.Hour)
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	timers.fire(t, sipRing)
	sendSIP(t, h, pplsipSrc, failedAck)
	require.Len(t, h.produced, 5)
	require.Equal(t, connection.EndClientClose, h.produced[4].endReason)
	require.Equal(t, []string{"100", "180", "486"}, statuses(summarizeSIP(t, h.produced[4].decoded)))
	require.Equal(t, []string{"busy/3", "busy/3", "busy/3"}, writeVariants(t, h.produced[4].decoded))
	require.Empty(t, timers.pending())

	// the memory holds what visit 3 did; visit 4 wraps around to answer
	advance(time.Hour)
	v := sipRecall.Begin("sip", pplsipSrc.IP, len(sipproto.Variants))
	require.Equal(t, 4, v.Number)
	require.Equal(t, 0, v.Variant)
	require.Equal(t, recall.Summary{
		Variant:   "busy",
		Commands:  []string{"INVITE", "ACK"},
		Paths:     []string{"sip:14500972598112101@1.2.3.4"},
		UserAgent: "pplsip",
		Events:    1,
	}, v.Previous)
}

func TestHandleSIPReturningSourceAuthUnackedTimesOut(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	advance := stubSIPRecall(t)
	h := &recordingHoneypot{}

	sendSIP(t, h, pplsipSrc, voipRegisterRead1)
	advance(time.Hour)
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	// the 401 is resent at T1 backoff until 64*T1 passes without an ACK
	for _, d := range []time.Duration{sipT1, 2 * sipT1, 4 * sipT1, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2, sipT2} {
		timers.fire(t, d)
	}
	require.Len(t, h.produced, 2)
	require.Equal(t, connection.EndTimeout, h.produced[1].endReason)
	for _, s := range statuses(summarizeSIP(t, h.produced[1].decoded)) {
		require.Equal(t, "401", s)
	}
}
