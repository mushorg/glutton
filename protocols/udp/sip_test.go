package udp

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mushorg/glutton/connection"
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

	wantReply := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 185.243.5.243:49618;branch=z9hG4bK-d87543-987333414-1--d87543-;rport\r\n" +
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
}

func TestHandleSIPInviteAnswered(t *testing.T) {
	stubSIPResponder(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("51.75.106.116"), Port: 65145}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, pplsipInviteRead1, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)

	dialog := "Via: SIP/2.0/UDP 0.0.0.0:65145;branch=z9hG4bK951917159\r\n" +
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
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	write := func(status, payload string) parsedSIP {
		return parsedSIP{
			Direction: "write",
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
