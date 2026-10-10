package udp

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/hiflying"
)

const (
	maxHiFlyingPayload = 1024
	// One discovery reply per source per hiflyingDiscoveryInterval, and at
	// most hiflyingMaxATReplies AT replies per source per interval, so the
	// sensor is no useful reflector.
	hiflyingDiscoveryInterval = time.Minute
	hiflyingMaxATReplies      = 32
	// A source stays known (and may enter command mode) this long after its
	// last datagram, as a module keeps its assist session.
	hiflyingSessionTTL  = 5 * time.Minute
	maxHiFlyingSessions = 4096
)

// hiflyingNow is the session clock; tests replace it.
var hiflyingNow = time.Now

type parsedHiFlying struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Path      string `json:"path,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type hiflyingSession struct {
	lastSeen      time.Time
	lastDiscovery time.Time
	atMode        bool
	window        time.Time
	replies       int
}

type hiflyingSessions struct {
	mu sync.Mutex
	m  map[string]*hiflyingSession
}

var hiflyingState = &hiflyingSessions{m: map[string]*hiflyingSession{}}

// get returns the live session for ip, creating one when create is set.
// Callers hold s.mu.
func (s *hiflyingSessions) get(ip string, now time.Time, create bool) *hiflyingSession {
	if sess, ok := s.m[ip]; ok && now.Sub(sess.lastSeen) < hiflyingSessionTTL {
		return sess
	}
	delete(s.m, ip)
	if !create {
		return nil
	}
	if len(s.m) >= maxHiFlyingSessions {
		for k, sess := range s.m {
			if now.Sub(sess.lastSeen) >= hiflyingSessionTTL {
				delete(s.m, k)
			}
		}
		if len(s.m) >= maxHiFlyingSessions {
			return nil
		}
	}
	sess := &hiflyingSession{lastSeen: now}
	s.m[ip] = sess
	return sess
}

// active reports whether ip ran discovery recently, so follow-up "+ok"/AT
// datagrams on any port belong to this handler.
func (s *hiflyingSessions) active(ip string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(ip, now, false) != nil
}

// step advances the session of ip for req and reports whether to reply.
func (s *hiflyingSessions) step(ip string, req hiflying.Request, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.get(ip, now, req.Kind == hiflying.KindDiscover)
	if sess == nil {
		return false
	}
	sess.lastSeen = now
	switch req.Kind {
	case hiflying.KindDiscover:
		sess.atMode = false
		if !sess.lastDiscovery.IsZero() && now.Sub(sess.lastDiscovery) < hiflyingDiscoveryInterval {
			return false
		}
		sess.lastDiscovery = now
		return true
	case hiflying.KindEnterAT:
		sess.atMode = true
		return false
	case hiflying.KindAT:
		if !sess.atMode {
			return false
		}
		if now.Sub(sess.window) >= hiflyingDiscoveryInterval {
			sess.window, sess.replies = now, 0
		}
		if sess.replies >= hiflyingMaxATReplies {
			return false
		}
		sess.replies++
		if req.Verb == "Q" {
			sess.atMode = false
		}
		return true
	}
	return false
}

// looksLikeHiFlying matches the discovery password on any port, and "+ok"/AT
// commands from a source that ran discovery recently.
func looksLikeHiFlying(srcAddr *net.UDPAddr, data []byte) bool {
	if hiflying.LooksLikeDiscovery(data) {
		return true
	}
	return hiflying.LooksLikeCommand(data) && hiflyingState.active(srcAddr.IP.String(), hiflyingNow())
}

// HandleHiFlying emulates a Hi-Flying Wi-Fi serial module's udp/48899
// configuration service: the discovery password gets "<ip>,<mac>,<module
// id>", "+ok" enters command mode silently, and AT commands get canned
// values. AT commands are only answered in command mode, as on a module.
func HandleHiFlying(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxHiFlyingPayload))
	copy(payload, data[:len(payload)])

	events := []parsedHiFlying{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("hiflying", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedHiFlying](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "hiflying"), producer.ErrAttr(err))
		}
	}()

	req := hiflying.Parse(payload)
	if req.Masked != nil {
		payload = req.Masked
	}
	events = append(events, parsedHiFlying{
		Direction: "read",
		Command:   req.Command(),
		Path:      req.Args,
		Payload:   payload,
		Truncated: len(data) > maxHiFlyingPayload,
	})

	logger.Info("HiFlying request received",
		slog.String("handler", "hiflying"),
		slog.String("protocol", "hiflying"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", req.Command()),
	)

	if req.Kind == hiflying.KindUnknown {
		return nil
	}
	if !hiflyingState.step(srcAddr.IP.String(), req, hiflyingNow()) {
		if req.Kind != hiflying.KindEnterAT {
			logger.Debug("HiFlying datagram not answered", slog.String("protocol", "hiflying"), slog.String("src_ip", srcAddr.IP.String()), slog.String("command", req.Command()))
		}
		return nil
	}

	mod := hiflying.ModuleFor([]byte(dstAddr.IP.String()))
	var resp []byte
	var status string
	if req.Kind == hiflying.KindDiscover {
		resp, status = hiflying.BuildDiscoveryReply(mod), hiflying.StatusDiscoverReply
	} else {
		resp, status = hiflying.BuildATReply(mod, req)
	}
	events = append(events, parsedHiFlying{
		Direction: "write",
		Command:   req.Command(),
		Status:    status,
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send HiFlying reply", slog.String("protocol", "hiflying"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
