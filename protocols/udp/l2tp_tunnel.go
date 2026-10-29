package udp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	l2tpproto "github.com/mushorg/glutton/protocols/udp/l2tp"
	"github.com/spf13/viper"
)

const (
	// maxL2TPTunnelFrames caps the frames kept per tunnel; reaching it
	// produces the tunnel with endReason max_frames.
	maxL2TPTunnelFrames = 48
	// maxL2TPTunnels caps the open tunnels; when full, the least recently
	// active one is produced with endReason evicted.
	maxL2TPTunnels = 256
	// maxL2TPSessions caps the sessions (ICRQs) one tunnel answers.
	maxL2TPSessions = 4
	// maxL2TPConfigureRequests caps the LCP Configure-Requests the honeypot
	// sends per session (initial plus re-proposals after a Nak).
	maxL2TPConfigureRequests = 3
)

// l2tpTimer is the part of *time.Timer the tunnel uses.
type l2tpTimer interface {
	Stop() bool
}

// l2tpAfterFunc schedules the tunnel idle flush; tests swap it.
var l2tpAfterFunc = func(d time.Duration, f func()) l2tpTimer {
	return time.AfterFunc(d, f)
}

// l2tpIdle overrides the tunnel idle timeout in tests. When zero, production
// uses conn_timeout (default 45s).
var l2tpIdle time.Duration

func l2tpIdleDuration() time.Duration {
	if l2tpIdle > 0 {
		return l2tpIdle
	}
	if secs := viper.GetInt("conn_timeout"); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 45 * time.Second
}

// l2tpRandID picks the honeypot's non-zero tunnel and session IDs; tests
// swap it.
var l2tpRandID = func() uint16 {
	return uint16(1 + rand.N(0xffff))
}

// l2tpRandUint32 picks LCP magic numbers; tests swap it.
var l2tpRandUint32 = rand.Uint32

// l2tpRandBytes fills CHAP challenges; tests swap it.
var l2tpRandBytes = func(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Uint32())
	}
	return b
}

const l2tpAuthFailed = "Authentication failed"

func l2tpTunnelKey(src *net.UDPAddr, localTID uint16) string {
	return src.String() + "|" + strconv.Itoa(int(localTID))
}

type l2tpTunnelTable struct {
	mu      sync.Mutex
	max     int
	tunnels map[string]*l2tpTunnel
	// clock orders tunnels by last activity for eviction
	clock atomic.Uint64
}

func newL2TPTunnelTable(max int) *l2tpTunnelTable {
	return &l2tpTunnelTable{max: max, tunnels: map[string]*l2tpTunnel{}}
}

// l2tpTunnels tracks open L2TP control connections across datagrams.
var l2tpTunnels = newL2TPTunnelTable(maxL2TPTunnels)

func (t *l2tpTunnelTable) get(key string) *l2tpTunnel {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tunnels[key]
}

// byPeer finds the tunnel a retransmitted SCCRQ belongs to.
func (t *l2tpTunnelTable) byPeer(src *net.UDPAddr, peerTID uint16) *l2tpTunnel {
	prefix := src.String() + "|"
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, tun := range t.tunnels {
		if strings.HasPrefix(key, prefix) && tun.peerTID == peerTID {
			return tun
		}
	}
	return nil
}

// open registers a new tunnel from src under a free random local tunnel ID.
// A full table first evicts its least recently active tunnel, which the
// caller must finish.
func (t *l2tpTunnelTable) open(src *net.UDPAddr, create func(key string, localTID uint16) *l2tpTunnel) (tun, evicted *l2tpTunnel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tunnels) >= t.max {
		for _, cand := range t.tunnels {
			if evicted == nil || cand.lastSeen() < evicted.lastSeen() {
				evicted = cand
			}
		}
		if evicted != nil {
			delete(t.tunnels, evicted.key)
		}
	}
	localTID := l2tpRandID()
	for t.tunnels[l2tpTunnelKey(src, localTID)] != nil {
		localTID = l2tpRandID()
	}
	key := l2tpTunnelKey(src, localTID)
	tun = create(key, localTID)
	t.tunnels[key] = tun
	return tun, evicted
}

func (t *l2tpTunnelTable) remove(key string, expected *l2tpTunnel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.tunnels[key]; ok && current == expected {
		delete(t.tunnels, key)
	}
}

// l2tpSession is one call (ICRQ) inside a tunnel and its PPP negotiation.
type l2tpSession struct {
	localSID, peerSID uint16
	icrp              []byte // replayed when the ICRQ is retransmitted

	acf       bool   // mirror the peer's PPP address/control field
	authProto uint16 // authentication the honeypot demands in LCP
	authAlg   uint8  // CHAP algorithm
	magic     uint32
	lcpID     uint8 // ID of the honeypot's latest Configure-Request
	confReqs  int
	challenge []byte
	chapID    uint8
}

// l2tpTunnel collects the frames of one control connection and its sessions
// and produces them as one event when it ends.
type l2tpTunnel struct {
	mu       sync.Mutex
	key      string
	table    *l2tpTunnelTable
	src, dst *net.UDPAddr
	md       connection.Metadata
	logger   interfaces.Logger
	h        interfaces.Honeypot
	events   []parsedL2TP
	seen     uint64
	produced bool
	idle     l2tpTimer
	stopCtx  func() bool

	localTID, peerTID uint16
	ns                uint16 // Ns of the next control message the honeypot sends
	nr                uint16 // Ns expected next from the peer
	sccrp             []byte
	sessions          map[uint16]*l2tpSession // by the honeypot's session ID
}

// openL2TPTunnel answers an SCCRQ. A retransmit joins the tunnel it opened
// and gets the same SCCRP again.
func openL2TPTunnel(ctx context.Context, src, dst *net.UDPAddr, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, frame parsedL2TP) error {
	if t := l2tpTunnels.byPeer(src, frame.AssignedTunnelID); t != nil {
		if handled, err := t.handleControl(frame); handled {
			return err
		}
	}
	t, evicted := l2tpTunnels.open(src, func(key string, localTID uint16) *l2tpTunnel {
		t := &l2tpTunnel{
			key: key, table: l2tpTunnels, src: src, dst: dst, md: md, logger: logger, h: h,
			events: []parsedL2TP{}, seen: l2tpTunnels.clock.Add(1),
			localTID: localTID, peerTID: frame.AssignedTunnelID,
			sessions: map[uint16]*l2tpSession{},
		}
		// flush open tunnels on shutdown
		t.stopCtx = context.AfterFunc(ctx, func() { t.finish(connection.EndHandlerClose) })
		return t
	})
	if evicted != nil {
		evicted.finish(connection.EndEvicted)
	}
	_, err := t.handleControl(frame)
	return err
}

func (t *l2tpTunnel) lastSeen() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seen
}

// beginLocked records a read frame. It returns false when the tunnel was already
// produced, so the caller handles the datagram on its own.
func (t *l2tpTunnel) beginLocked(frame parsedL2TP) bool {
	if t.produced {
		return false
	}
	t.seen = t.table.clock.Add(1)
	t.events = append(t.events, frame)
	t.armIdleLocked()
	return true
}

// handleControl records one control message of the tunnel and answers it.
func (t *l2tpTunnel) handleControl(frame parsedL2TP) (bool, error) {
	t.mu.Lock()
	if !t.beginLocked(frame) {
		t.mu.Unlock()
		return false, nil
	}
	endReason, err := t.controlLocked(frame)
	if endReason == "" && len(t.events) >= maxL2TPTunnelFrames {
		endReason = connection.EndMaxFrames
	}
	t.mu.Unlock()
	if endReason != "" {
		t.finish(endReason)
	}
	return true, err
}

func (t *l2tpTunnel) controlLocked(frame parsedL2TP) (string, error) {
	if frame.MessageName == "ZLB" {
		return "", nil
	}
	fresh := frame.Ns == t.nr
	if fresh {
		t.nr++
	}

	switch frame.MessageType {
	case l2tpMsgSCCRQ:
		if t.sccrp == nil {
			t.sccrp = buildSCCRP(t.peerTID, t.localTID, t.ns, t.nr)
			t.ns++
		}
		return t.writeControlLocked(t.sccrp, parsedL2TP{
			MessageType:      l2tpMsgSCCRP,
			HostName:         l2tpHoneypotHostName,
			VendorName:       l2tpHoneypotVendorName,
			TunnelID:         t.peerTID,
			AssignedTunnelID: t.localTID,
		})
	case l2tpMsgICRQ:
		return t.icrqLocked(frame, fresh)
	case l2tpMsgCDN:
		for sid, s := range t.sessions {
			if s.peerSID == frame.AssignedSessionID || sid == frame.SessionID {
				delete(t.sessions, sid)
			}
		}
	case l2tpMsgStopCCN:
		if _, err := t.zlbLocked(); err != nil {
			return connection.EndWriteError, err
		}
		return connection.EndClientClose, nil
	}
	// SCCCN, HELLO, ICCN, CDN and the rest are acknowledged with a ZLB
	return t.zlbLocked()
}

func (t *l2tpTunnel) icrqLocked(frame parsedL2TP, fresh bool) (string, error) {
	for _, s := range t.sessions {
		if s.peerSID == frame.AssignedSessionID {
			// retransmitted ICRQ
			return t.writeControlLocked(s.icrp, parsedL2TP{
				MessageType:       l2tpMsgICRP,
				TunnelID:          t.peerTID,
				SessionID:         s.peerSID,
				AssignedSessionID: s.localSID,
			})
		}
	}
	if !fresh || frame.AssignedSessionID == 0 || len(t.sessions) >= maxL2TPSessions {
		return t.zlbLocked()
	}
	localSID := l2tpRandID()
	for t.sessions[localSID] != nil {
		localSID = l2tpRandID()
	}
	s := &l2tpSession{
		localSID:  localSID,
		peerSID:   frame.AssignedSessionID,
		authProto: l2tpproto.ProtoPAP,
		magic:     l2tpRandUint32(),
	}
	s.icrp = buildICRP(t.peerTID, s.peerSID, s.localSID, t.ns, t.nr)
	t.ns++
	t.sessions[localSID] = s
	return t.writeControlLocked(s.icrp, parsedL2TP{
		MessageType:       l2tpMsgICRP,
		TunnelID:          t.peerTID,
		SessionID:         s.peerSID,
		AssignedSessionID: s.localSID,
	})
}

func (t *l2tpTunnel) zlbLocked() (string, error) {
	return t.writeControlLocked(buildL2TPControl(t.peerTID, 0, t.ns, t.nr, nil), parsedL2TP{TunnelID: t.peerTID})
}

// writeControlLocked sends a control message and records it; frame carries
// the fields beyond those parsed from data.
func (t *l2tpTunnel) writeControlLocked(data []byte, frame parsedL2TP) (string, error) {
	frame.Direction = "write"
	if frame.MessageType != 0 {
		frame.MessageName = l2tpMessageName(frame.MessageType)
	} else {
		frame.MessageName = "ZLB"
	}
	frame.Command = frame.MessageName
	frame.Status = frame.MessageName
	frame.Ns = binary.BigEndian.Uint16(data[8:10])
	frame.Nr = binary.BigEndian.Uint16(data[10:12])
	return t.writeLocked(data, frame)
}

func (t *l2tpTunnel) writeLocked(data []byte, frame parsedL2TP) (string, error) {
	frame.Direction = "write"
	frame.Payload = data
	t.events = append(t.events, frame)
	if err := t.h.ReplyUDP(t.src, t.dst, data); err != nil {
		t.logger.Error("Failed to reply to L2TP message", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
		return connection.EndWriteError, err
	}
	return "", nil
}

// handleData records one PPP frame of a session and answers LCP, PAP and
// CHAP the way an LNS demanding authentication would, rejecting every
// credential.
func (t *l2tpTunnel) handleData(frame parsedL2TP, hdr l2tpproto.DataHeader, pkt l2tpproto.Packet) (bool, error) {
	t.mu.Lock()
	if !t.beginLocked(frame) {
		t.mu.Unlock()
		return false, nil
	}
	var endReason string
	var err error
	if s := t.sessions[hdr.SessionID]; s != nil {
		endReason, err = t.pppLocked(s, frame, pkt)
	}
	if endReason == "" && len(t.events) >= maxL2TPTunnelFrames {
		endReason = connection.EndMaxFrames
	}
	t.mu.Unlock()
	if endReason != "" {
		t.finish(endReason)
	}
	return true, err
}

func (t *l2tpTunnel) pppLocked(s *l2tpSession, frame parsedL2TP, pkt l2tpproto.Packet) (string, error) {
	s.acf = pkt.ACF
	switch pkt.Protocol {
	case l2tpproto.ProtoLCP:
		return t.lcpLocked(s, pkt)
	case l2tpproto.ProtoPAP:
		if pkt.Code != l2tpproto.CodePAPAuthRequest {
			return "", nil
		}
		t.logAuth(frame)
		return t.sendPPPLocked(s, l2tpproto.ProtoPAP, l2tpproto.CodePAPAuthNak, pkt.ID, l2tpproto.PAPMessage(l2tpAuthFailed), "")
	case l2tpproto.ProtoCHAP:
		if pkt.Code != l2tpproto.CodeCHAPResponse || s.challenge == nil || pkt.ID != s.chapID {
			return "", nil
		}
		t.logAuth(frame)
		msg := l2tpAuthFailed
		if s.authAlg == l2tpproto.CHAPMSCHAPv2 {
			msg = "E=691 R=0 C=" + strings.ToUpper(hex.EncodeToString(s.challenge)) + " V=3"
		}
		return t.sendPPPLocked(s, l2tpproto.ProtoCHAP, l2tpproto.CodeCHAPFailure, pkt.ID, []byte(msg), "")
	}
	return "", nil
}

func (t *l2tpTunnel) lcpLocked(s *l2tpSession, pkt l2tpproto.Packet) (string, error) {
	switch pkt.Code {
	case l2tpproto.CodeConfigureRequest:
		if end, err := t.sendPPPLocked(s, l2tpproto.ProtoLCP, l2tpproto.CodeConfigureAck, pkt.ID, pkt.Data, ""); end != "" {
			return end, err
		}
		if s.confReqs == 0 {
			return t.configureRequestLocked(s)
		}
	case l2tpproto.CodeConfigureAck:
		if pkt.ID == s.lcpID && s.authProto == l2tpproto.ProtoCHAP && s.challenge == nil {
			s.challenge = l2tpRandBytes(16)
			s.chapID = s.lcpID + 1
			return t.sendPPPLocked(s, l2tpproto.ProtoCHAP, l2tpproto.CodeCHAPChallenge, s.chapID,
				l2tpproto.CHAPChallenge(s.challenge, l2tpHoneypotHostName), l2tpproto.AuthName(s.authProto, s.authAlg))
		}
	case l2tpproto.CodeConfigureNak:
		// the peer asks for another authentication protocol
		opts, err := l2tpproto.ParseOptions(pkt.Data)
		if err != nil || pkt.ID != s.lcpID || s.confReqs >= maxL2TPConfigureRequests {
			return "", nil
		}
		proto, alg, ok := l2tpproto.AuthOption(opts)
		if !ok || (proto == l2tpproto.ProtoCHAP && alg != l2tpproto.CHAPMD5 && alg != l2tpproto.CHAPMSCHAPv2) ||
			(proto != l2tpproto.ProtoCHAP && proto != l2tpproto.ProtoPAP) {
			return "", nil
		}
		s.authProto, s.authAlg = proto, alg
		return t.configureRequestLocked(s)
	case l2tpproto.CodeEchoRequest:
		data := append([]byte{}, pkt.Data...)
		if len(data) >= 4 {
			binary.BigEndian.PutUint32(data[0:4], s.magic)
		}
		return t.sendPPPLocked(s, l2tpproto.ProtoLCP, l2tpproto.CodeEchoReply, pkt.ID, data, "")
	case l2tpproto.CodeTerminateRequest:
		return t.sendPPPLocked(s, l2tpproto.ProtoLCP, l2tpproto.CodeTerminateAck, pkt.ID, nil, "")
	}
	return "", nil
}

func (t *l2tpTunnel) configureRequestLocked(s *l2tpSession) (string, error) {
	s.confReqs++
	s.lcpID++
	opts := l2tpproto.ConfigureRequestOptions(s.authProto, s.authAlg, s.magic)
	return t.sendPPPLocked(s, l2tpproto.ProtoLCP, l2tpproto.CodeConfigureRequest, s.lcpID, opts, l2tpproto.AuthName(s.authProto, s.authAlg))
}

func (t *l2tpTunnel) sendPPPLocked(s *l2tpSession, proto uint16, code, id uint8, data []byte, auth string) (string, error) {
	msg := l2tpproto.BuildData(t.peerTID, s.peerSID, l2tpproto.BuildPPP(s.acf, proto, code, id, data))
	command := l2tpproto.Command(proto, code)
	return t.writeLocked(msg, parsedL2TP{
		Command:      command,
		Status:       command,
		TunnelID:     t.peerTID,
		SessionID:    s.peerSID,
		PPPProtocol:  l2tpproto.ProtocolName(proto),
		AuthProtocol: auth,
	})
}

func (t *l2tpTunnel) logAuth(frame parsedL2TP) {
	t.logger.Info("L2TP PPP authentication attempt",
		slog.String("handler", "l2tp"),
		slog.String("protocol", "l2tp"),
		slog.String("src_ip", t.src.IP.String()),
		slog.Int("src_port", t.src.Port),
		slog.Int("dest_port", t.dst.Port),
		slog.String("auth_protocol", frame.AuthProtocol),
		slog.String("username", frame.Username),
	)
}

func (t *l2tpTunnel) armIdleLocked() {
	if t.idle != nil {
		t.idle.Stop()
	}
	t.idle = l2tpAfterFunc(l2tpIdleDuration(), func() { t.finish(connection.EndTimeout) })
}

// finish produces the tunnel once and drops it from the table.
func (t *l2tpTunnel) finish(endReason string) {
	t.mu.Lock()
	if t.produced {
		t.mu.Unlock()
		return
	}
	t.produced = true
	if t.idle != nil {
		t.idle.Stop()
		t.idle = nil
	}
	if t.stopCtx != nil {
		t.stopCtx()
	}
	events := t.events
	md := t.md
	md.EndReason = endReason
	t.mu.Unlock()

	t.table.remove(t.key, t)
	if err := t.h.ProduceUDP("l2tp", t.src, t.dst, md, helpers.FirstOrEmpty[parsedL2TP](events).Payload, events); err != nil {
		t.logger.Error("Failed to produce message", slog.String("protocol", "l2tp"), producer.ErrAttr(err))
	}
}
