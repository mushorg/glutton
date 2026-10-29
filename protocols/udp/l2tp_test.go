package udp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	l2tpproto "github.com/mushorg/glutton/protocols/udp/l2tp"
	"github.com/stretchr/testify/require"
)

func l2tpDraytekSCCRQ() []byte {
	// Captured scanner probe: Host Name=Vigor, Vendor Name=Draytek
	raw, err := base64.StdEncoding.DecodeString("yAIAWAAAAAAAAAABgAgAAAAAAAGACAAAAAIBAIALAAAAB1ZpZ29ygAoAAAADAAAAA4AIAAAACemZgAoAAAAEAAAAAwAIAAAABgABAA0AAAAIRHJheXRlaw==")
	if err != nil {
		panic(err)
	}
	return raw
}

// read frame 1 of https://ochi.mushmush.org/events/629e637d-9da5-4160-89eb-d315fb268653
// (SCCRQ, Host Name=ubuntu-5fdfd1fd, Vendor Name=Ubuntu 24.04, Assigned Tunnel ID 51150)
var l2tpUbuntuRead1 = []byte{
	0xc8, 0x02, 0x00, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x80, 0x0a, 0x00, 0x00,
	0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
	0x80, 0x15, 0x00, 0x00, 0x00, 0x07, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2d, 0x35, 0x66, 0x64,
	0x66, 0x64, 0x31, 0x66, 0x64, 0x80, 0x12, 0x00, 0x00, 0x00, 0x08, 0x55, 0x62, 0x75, 0x6e, 0x74,
	0x75, 0x20, 0x32, 0x34, 0x2e, 0x30, 0x34, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x05, 0x52, 0x5c, 0x5b,
	0x9b, 0x16, 0x9e, 0xab, 0x64, 0x80, 0x08, 0x00, 0x00, 0x00, 0x09, 0xc7, 0xce, 0x80, 0x08, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0x0a,
}

const (
	testL2TPPeerTID  = 0xc7ce
	testL2TPLocalTID = 0x1001
	testL2TPPeerSID  = 0x0042
	testL2TPLocalSID = 0x1002
	testL2TPMagic    = 0xa1b2c3d4
)

type fakeL2TPTimer struct {
	mu      sync.Mutex
	f       func()
	stopped bool
}

func (t *fakeL2TPTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

type fakeL2TPTimers struct {
	mu     sync.Mutex
	timers []*fakeL2TPTimer
}

// fireIdle runs the idle timers that are still armed.
func (ft *fakeL2TPTimers) fireIdle() {
	ft.mu.Lock()
	timers := append([]*fakeL2TPTimer(nil), ft.timers...)
	ft.mu.Unlock()
	for _, t := range timers {
		t.mu.Lock()
		armed := !t.stopped
		t.stopped = true
		t.mu.Unlock()
		if armed {
			t.f()
		}
	}
}

// stubL2TP gives the test a fresh tunnel table, fixed IDs (local tunnel
// 0x1001, then session 0x1002, ...), a fixed magic number and challenge, and
// idle timers it fires by hand.
func stubL2TP(t *testing.T) *fakeL2TPTimers {
	t.Helper()
	ft := &fakeL2TPTimers{}
	origTable, origAfter, origID, origU32, origBytes := l2tpTunnels, l2tpAfterFunc, l2tpRandID, l2tpRandUint32, l2tpRandBytes
	l2tpTunnels = newL2TPTunnelTable(maxL2TPTunnels)
	next := uint16(testL2TPLocalTID)
	l2tpRandID = func() uint16 {
		id := next
		next++
		return id
	}
	l2tpRandUint32 = func() uint32 { return testL2TPMagic }
	l2tpRandBytes = func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}
	l2tpAfterFunc = func(_ time.Duration, f func()) l2tpTimer {
		tm := &fakeL2TPTimer{f: f}
		ft.mu.Lock()
		ft.timers = append(ft.timers, tm)
		ft.mu.Unlock()
		return tm
	}
	t.Cleanup(func() {
		l2tpTunnels, l2tpAfterFunc, l2tpRandID, l2tpRandUint32, l2tpRandBytes = origTable, origAfter, origID, origU32, origBytes
	})
	return ft
}

func l2tpTestAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 8350}, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1701}
}

// l2tpCtl builds a control message from the client to the honeypot tunnel.
func l2tpCtl(sessionID, ns, nr uint16, msgType uint16, extra ...[]byte) []byte {
	avps := encodeL2TPAVP(true, l2tpAttrMessageType, l2tpU16(msgType))
	for _, e := range extra {
		avps = append(avps, e...)
	}
	return buildL2TPControl(testL2TPLocalTID, sessionID, ns, nr, avps)
}

// l2tpPPP builds a data message from the client carrying a PPP packet.
func l2tpPPP(proto uint16, code, id uint8, data []byte) []byte {
	return l2tpproto.BuildData(testL2TPLocalTID, testL2TPLocalSID, l2tpproto.BuildPPP(true, proto, code, id, data))
}

func handleL2TP(t *testing.T, h *recordingHoneypot, src, dst *net.UDPAddr, data []byte) {
	t.Helper()
	require.NoError(t, HandleL2TP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
}

// openL2TPSession drives SCCRQ, SCCCN, ICRQ and ICCN and checks the replies.
func openL2TPSession(t *testing.T, h *recordingHoneypot, src, dst *net.UDPAddr) {
	t.Helper()
	handleL2TP(t, h, src, dst, l2tpUbuntuRead1)
	handleL2TP(t, h, src, dst, l2tpCtl(0, 1, 1, l2tpMsgSCCCN))
	handleL2TP(t, h, src, dst, l2tpCtl(0, 2, 1, l2tpMsgICRQ, encodeL2TPAVP(true, l2tpAttrAssignedSessionID, l2tpU16(testL2TPPeerSID))))
	handleL2TP(t, h, src, dst, l2tpCtl(testL2TPLocalSID, 3, 2, l2tpMsgICCN))

	require.Len(t, h.replies, 4)
	require.Equal(t, buildSCCRP(testL2TPPeerTID, testL2TPLocalTID, 0, 1), h.replies[0])
	require.Equal(t, buildL2TPControl(testL2TPPeerTID, 0, 1, 2, nil), h.replies[1], "ZLB acks SCCCN")
	require.Equal(t, buildICRP(testL2TPPeerTID, testL2TPPeerSID, testL2TPLocalSID, 1, 3), h.replies[2])
	require.Equal(t, buildL2TPControl(testL2TPPeerTID, 0, 2, 4, nil), h.replies[3], "ZLB acks ICCN")
}

func l2tpFrames(t *testing.T, h *recordingHoneypot) []parsedL2TP {
	t.Helper()
	require.Len(t, h.produced, 1)
	require.Equal(t, "l2tp", h.produced[0].handler)
	events, ok := h.produced[0].decoded.([]parsedL2TP)
	require.True(t, ok)
	return events
}

func l2tpCommands(events []parsedL2TP) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Direction + " " + e.Command
	}
	return out
}

func TestHandleL2TPSCCRQ(t *testing.T) {
	timers := stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	payload := l2tpDraytekSCCRQ()

	handleL2TP(t, h, src, dst, payload)
	require.Empty(t, h.produced, "tunnel stays open for the SCCCN")
	require.Len(t, h.replies, 1)

	timers.fireIdle()
	require.Equal(t, payload, h.produced[0].payload)
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	events := l2tpFrames(t, h)
	require.Len(t, events, 2)

	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, uint16(1), events[0].MessageType)
	require.Equal(t, "SCCRQ", events[0].MessageName)
	require.Equal(t, "SCCRQ", events[0].Command)
	require.Equal(t, "Vigor", events[0].HostName)
	require.Equal(t, "Draytek", events[0].VendorName)
	require.Equal(t, uint16(0xe999), events[0].AssignedTunnelID)
	require.Equal(t, payload, events[0].Payload)

	require.Equal(t, parsedL2TP{
		Direction:        "write",
		Command:          "SCCRP",
		Status:           "SCCRP",
		MessageType:      l2tpMsgSCCRP,
		MessageName:      "SCCRP",
		HostName:         l2tpHoneypotHostName,
		VendorName:       l2tpHoneypotVendorName,
		TunnelID:         0xe999,
		AssignedTunnelID: testL2TPLocalTID,
		Nr:               1,
		Payload:          h.replies[0],
	}, events[1])

	reply, err := parseL2TP(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, "SCCRP", reply.MessageName)
	require.Equal(t, uint16(0xe999), reply.TunnelID)
	require.Equal(t, uint16(testL2TPLocalTID), reply.AssignedTunnelID)
	require.Equal(t, uint16(0), reply.Ns)
	require.Equal(t, uint16(1), reply.Nr)
	require.Less(t, len(h.replies[0]), len(payload), "SCCRP must not amplify")
}

func TestHandleL2TPPAPSession(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	openL2TPSession(t, h, src, dst)

	// client LCP Configure-Request: MRU 1400, magic
	clientOpts := []byte{0x01, 0x04, 0x05, 0x78, 0x05, 0x06, 0x11, 0x22, 0x33, 0x44}
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeConfigureRequest, 1, clientOpts))
	require.Len(t, h.replies, 6)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoLCP, l2tpproto.CodeConfigureAck, 1, clientOpts)), h.replies[4])
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoLCP, l2tpproto.CodeConfigureRequest, 1,
			l2tpproto.ConfigureRequestOptions(l2tpproto.ProtoPAP, 0, testL2TPMagic))), h.replies[5])

	// client acks our request, then authenticates
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeConfigureAck, 1,
		l2tpproto.ConfigureRequestOptions(l2tpproto.ProtoPAP, 0, testL2TPMagic)))
	require.Len(t, h.replies, 6, "nothing to send after the Ack under PAP")
	pap := []byte{5, 'a', 'd', 'm', 'i', 'n', 6, 'v', 'p', 'n', '1', '2', '3'}
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoPAP, l2tpproto.CodePAPAuthRequest, 7, pap))
	require.Len(t, h.replies, 7)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoPAP, l2tpproto.CodePAPAuthNak, 7, l2tpproto.PAPMessage("Authentication failed"))), h.replies[6])

	// client gives up
	handleL2TP(t, h, src, dst, l2tpCtl(0, 4, 2, l2tpMsgStopCCN))
	require.Len(t, h.replies, 8)
	require.Equal(t, buildL2TPControl(testL2TPPeerTID, 0, 2, 5, nil), h.replies[7])

	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	require.Equal(t, l2tpUbuntuRead1, h.produced[0].payload)
	events := l2tpFrames(t, h)
	require.Equal(t, []string{
		"read SCCRQ", "write SCCRP",
		"read SCCCN", "write ZLB",
		"read ICRQ", "write ICRP",
		"read ICCN", "write ZLB",
		"read LCP Configure-Request", "write LCP Configure-Ack", "write LCP Configure-Request",
		"read LCP Configure-Ack",
		"read PAP Authenticate-Request", "write PAP Authenticate-Nak",
		"read StopCCN", "write ZLB",
	}, l2tpCommands(events))

	require.Equal(t, uint16(testL2TPPeerSID), events[4].AssignedSessionID)
	require.Equal(t, uint16(testL2TPLocalSID), events[5].AssignedSessionID)
	require.Equal(t, "ICRP", events[5].Status)
	require.Equal(t, "PAP", events[10].AuthProtocol)
	require.Equal(t, "LCP", events[10].PPPProtocol)
	require.Equal(t, "PAP", events[11].AuthProtocol)

	auth := events[12]
	require.Equal(t, "read", auth.Direction)
	require.Equal(t, "PAP", auth.PPPProtocol)
	require.Equal(t, "PAP", auth.AuthProtocol)
	require.Equal(t, "admin", auth.Username)
	require.Equal(t, "vpn123", auth.Password)
	require.Equal(t, uint16(testL2TPLocalTID), auth.TunnelID)
	require.Equal(t, uint16(testL2TPLocalSID), auth.SessionID)
	require.Equal(t, "PAP Authenticate-Nak", events[13].Status)
	for i, e := range events {
		if e.Direction == "write" {
			require.NotEmpty(t, e.Status, "write frame %d", i)
		}
	}
	require.Nil(t, l2tpTunnels.get(l2tpTunnelKey(src, testL2TPLocalTID)), "StopCCN drops the tunnel")
}

func TestHandleL2TPCHAPAfterNak(t *testing.T) {
	timers := stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	openL2TPSession(t, h, src, dst)

	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeConfigureRequest, 1, []byte{0x05, 0x06, 1, 2, 3, 4}))
	require.Len(t, h.replies, 6)

	// client refuses PAP and asks for MS-CHAPv2
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeConfigureNak, 1, []byte{0x03, 0x05, 0xc2, 0x23, 0x81}))
	require.Len(t, h.replies, 7)
	want := l2tpproto.ConfigureRequestOptions(l2tpproto.ProtoCHAP, l2tpproto.CHAPMSCHAPv2, testL2TPMagic)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoLCP, l2tpproto.CodeConfigureRequest, 2, want)), h.replies[6])

	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeConfigureAck, 2, want))
	require.Len(t, h.replies, 8)
	challenge := l2tpRandBytes(16)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoCHAP, l2tpproto.CodeCHAPChallenge, 3, l2tpproto.CHAPChallenge(challenge, l2tpHoneypotHostName))), h.replies[7])

	value := make([]byte, 49)
	value[0] = 0xab
	resp := append(append([]byte{49}, value...), "bob"...)
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoCHAP, l2tpproto.CodeCHAPResponse, 3, resp))
	require.Len(t, h.replies, 9)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoCHAP, l2tpproto.CodeCHAPFailure, 3,
			[]byte("E=691 R=0 C=000102030405060708090A0B0C0D0E0F V=3"))), h.replies[8])

	// LCP keepalive is answered with our magic
	handleL2TP(t, h, src, dst, l2tpPPP(l2tpproto.ProtoLCP, l2tpproto.CodeEchoRequest, 9, []byte{1, 2, 3, 4}))
	require.Len(t, h.replies, 10)
	require.Equal(t, l2tpproto.BuildData(testL2TPPeerTID, testL2TPPeerSID,
		l2tpproto.BuildPPP(true, l2tpproto.ProtoLCP, l2tpproto.CodeEchoReply, 9, binary.BigEndian.AppendUint32(nil, testL2TPMagic))), h.replies[9])

	timers.fireIdle()
	require.Equal(t, connection.EndTimeout, h.produced[0].endReason)
	events := l2tpFrames(t, h)
	require.Equal(t, []string{
		"read SCCRQ", "write SCCRP",
		"read SCCCN", "write ZLB",
		"read ICRQ", "write ICRP",
		"read ICCN", "write ZLB",
		"read LCP Configure-Request", "write LCP Configure-Ack", "write LCP Configure-Request",
		"read LCP Configure-Nak", "write LCP Configure-Request",
		"read LCP Configure-Ack", "write CHAP Challenge",
		"read CHAP Response", "write CHAP Failure",
		"read LCP Echo-Request", "write LCP Echo-Reply",
	}, l2tpCommands(events))
	require.Equal(t, "MS-CHAPv2", events[11].AuthProtocol)
	require.Equal(t, "MS-CHAPv2", events[12].AuthProtocol)
	require.Equal(t, "MS-CHAPv2", events[14].AuthProtocol)
	require.Equal(t, "bob", events[15].Username)
	require.Equal(t, hex.EncodeToString(value), events[15].CHAPResponse)
}

func TestHandleL2TPRetransmits(t *testing.T) {
	timers := stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()

	handleL2TP(t, h, src, dst, l2tpUbuntuRead1)
	handleL2TP(t, h, src, dst, l2tpUbuntuRead1)
	require.Len(t, h.replies, 2)
	require.Equal(t, h.replies[0], h.replies[1], "a retransmitted SCCRQ gets the same SCCRP")

	icrq := l2tpCtl(0, 1, 1, l2tpMsgICRQ, encodeL2TPAVP(true, l2tpAttrAssignedSessionID, l2tpU16(testL2TPPeerSID)))
	handleL2TP(t, h, src, dst, icrq)
	handleL2TP(t, h, src, dst, icrq)
	require.Len(t, h.replies, 4)
	require.Equal(t, h.replies[2], h.replies[3], "a retransmitted ICRQ gets the same ICRP")

	// the client's own ZLB is not answered
	handleL2TP(t, h, src, dst, buildL2TPControl(testL2TPLocalTID, 0, 2, 2, nil))
	require.Len(t, h.replies, 4)

	timers.fireIdle()
	events := l2tpFrames(t, h)
	require.Equal(t, []string{
		"read SCCRQ", "write SCCRP", "read SCCRQ", "write SCCRP",
		"read ICRQ", "write ICRP", "read ICRQ", "write ICRP",
		"read ZLB",
	}, l2tpCommands(events))
}

func TestHandleL2TPMaxFrames(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()

	handleL2TP(t, h, src, dst, l2tpUbuntuRead1)
	for ns := uint16(1); len(h.produced) == 0; ns++ {
		require.Less(t, ns, uint16(maxL2TPTunnelFrames), "cap never reached")
		handleL2TP(t, h, src, dst, l2tpCtl(0, ns, 1, l2tpMsgHELLO))
	}
	require.Equal(t, connection.EndMaxFrames, h.produced[0].endReason)
	require.Len(t, l2tpFrames(t, h), maxL2TPTunnelFrames)

	// the next HELLO matches no tunnel: its own event, no reply
	replies := len(h.replies)
	handleL2TP(t, h, src, dst, l2tpCtl(0, 99, 1, l2tpMsgHELLO))
	require.Len(t, h.produced, 2)
	require.Len(t, h.replies, replies)
}

func TestHandleL2TPContextFlush(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	ctx, cancel := context.WithCancel(context.Background())

	require.NoError(t, HandleL2TP(ctx, src, dst, l2tpUbuntuRead1, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.produced)
	cancel()
	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.produced) == 1
	}, time.Second, 5*time.Millisecond)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
}

func TestHandleL2TPDataWithoutTunnel(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	pap := []byte{1, 'u', 1, 'p'}
	payload := l2tpPPP(l2tpproto.ProtoPAP, l2tpproto.CodePAPAuthRequest, 1, pap)

	handleL2TP(t, h, src, dst, payload)
	require.Empty(t, h.replies)
	events := l2tpFrames(t, h)
	require.Len(t, events, 1)
	require.Equal(t, "PAP Authenticate-Request", events[0].Command)
	require.Equal(t, "u", events[0].Username)
	require.Equal(t, "p", events[0].Password)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleL2TPNonSCCRQ(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()

	// Minimal HELLO: header + Message Type AVP only
	payload := []byte{
		0xc8, 0x02, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06,
		0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
	}

	handleL2TP(t, h, src, dst, payload)
	require.Empty(t, h.replies)
	events := l2tpFrames(t, h)
	require.Len(t, events, 1)
	require.Equal(t, "HELLO", events[0].MessageName)
	require.Equal(t, uint16(6), events[0].MessageType)
}

func TestHandleL2TPShortPacket(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	payload := []byte{0xc8, 0x02}

	handleL2TP(t, h, src, dst, payload)
	require.Empty(t, h.replies)
	events := l2tpFrames(t, h)
	require.Len(t, events, 1)
	require.Equal(t, payload, events[0].Payload)
	require.Empty(t, events[0].MessageName)
}

func TestHandleL2TPMalformedData(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	payload := []byte{0x40, 0x02, 0x00, 0x30, 0x00, 0x01}

	handleL2TP(t, h, src, dst, payload)
	require.Empty(t, h.replies)
	events := l2tpFrames(t, h)
	require.Len(t, events, 1)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleL2TPOversize(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()
	payload := make([]byte, maxL2TPPayload+100)
	payload[0], payload[1] = 0xc8, 0x02

	handleL2TP(t, h, src, dst, payload)
	events := l2tpFrames(t, h)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxL2TPPayload)
}

func TestHandleL2TPEmptyPayload(t *testing.T) {
	stubL2TP(t)
	h := &recordingHoneypot{}
	src, dst := l2tpTestAddrs()

	handleL2TP(t, h, src, dst, nil)
	require.Len(t, h.produced, 1)
	require.Equal(t, "l2tp", h.produced[0].handler)
	require.Empty(t, h.replies)
}

func TestBuildSCCRPRoundTrip(t *testing.T) {
	resp := buildSCCRP(0xe999, 0x2222, 0, 1)
	require.GreaterOrEqual(t, len(resp), 12)
	require.Equal(t, uint16(len(resp)), binary.BigEndian.Uint16(resp[2:4]))

	frame, err := parseL2TP(resp)
	require.NoError(t, err)
	require.Equal(t, "SCCRP", frame.MessageName)
	require.Equal(t, uint16(0xe999), frame.TunnelID)
	require.Equal(t, uint16(0x2222), frame.AssignedTunnelID)
	require.Equal(t, l2tpHoneypotHostName, frame.HostName)
	require.Equal(t, l2tpHoneypotVendorName, frame.VendorName)
}

func TestBuildICRPRoundTrip(t *testing.T) {
	frame, err := parseL2TP(buildICRP(0xe999, 0x42, 0x77, 1, 3))
	require.NoError(t, err)
	require.Equal(t, "ICRP", frame.MessageName)
	require.Equal(t, uint16(0xe999), frame.TunnelID)
	require.Equal(t, uint16(0x42), frame.SessionID)
	require.Equal(t, uint16(0x77), frame.AssignedSessionID)
	require.Equal(t, uint16(1), frame.Ns)
	require.Equal(t, uint16(3), frame.Nr)
}

func TestParseL2TPZLB(t *testing.T) {
	frame, err := parseL2TP(buildL2TPControl(1, 0, 4, 5, nil))
	require.NoError(t, err)
	require.Equal(t, "ZLB", frame.MessageName)
	require.Equal(t, "ZLB", frame.Command)
	require.Equal(t, uint16(4), frame.Ns)
}

func TestParseL2TPDataMessage(t *testing.T) {
	// T-bit clear → data message
	_, err := parseL2TP([]byte{0x40, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01})
	require.Error(t, err)
}
