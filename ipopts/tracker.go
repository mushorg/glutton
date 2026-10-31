package ipopts

import (
	"net"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
)

// Config bounds the in-memory flow table.
type Config struct {
	Idle      time.Duration
	MaxFlows  int
	MaxFrames int
}

// Flow is one TCP 4-tuple's captured IP-option packets, ready to produce.
type Flow struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Started   time.Time
	LastSeen  time.Time
	Frames    []Frame
	EndReason string
}

// Tracker aggregates decoded packets into one Flow per 4-tuple.
type Tracker struct {
	cfg   Config
	mu    sync.Mutex
	flows map[string]*flowState
}

type flowState struct {
	flow Flow
}

// NewTracker returns an empty tracker. Zero Idle/MaxFlows/MaxFrames get
// defaults of 5s / 1024 / 32.
func NewTracker(cfg Config) *Tracker {
	if cfg.Idle <= 0 {
		cfg.Idle = 5 * time.Second
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 1024
	}
	if cfg.MaxFrames <= 0 {
		cfg.MaxFrames = 32
	}
	return &Tracker{
		cfg:   cfg,
		flows: make(map[string]*flowState),
	}
}

// Add appends a frame to the flow for pkt. direction is "read" (attacker →
// sensor) or "write" (sensor → attacker). Write packets are keyed by the
// swapped 4-tuple so they join the inbound flow. Returned flows are finished
// (evicted LRU, or this flow hit max_frames) and should be produced.
func (t *Tracker) Add(now time.Time, direction string, pkt *Packet) []Flow {
	if pkt == nil {
		return nil
	}
	srcIP, dstIP := pkt.SrcIP, pkt.DstIP
	srcPort, dstPort := pkt.SrcPort, pkt.DstPort
	if direction == "write" {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	key := flowKey(srcIP, srcPort, dstIP, dstPort)
	frame := pkt.Frame
	frame.Direction = direction

	t.mu.Lock()
	defer t.mu.Unlock()

	var flushed []Flow
	st := t.flows[key]
	if st == nil {
		if len(t.flows) >= t.cfg.MaxFlows {
			if evicted := t.evictLRULocked(now); evicted != nil {
				flushed = append(flushed, *evicted)
			}
		}
		st = &flowState{
			flow: Flow{
				SrcIP:    append(net.IP(nil), srcIP...),
				DstIP:    append(net.IP(nil), dstIP...),
				SrcPort:  srcPort,
				DstPort:  dstPort,
				Started:  now,
				LastSeen: now,
			},
		}
		t.flows[key] = st
	}
	st.flow.LastSeen = now
	st.flow.Frames = append(st.flow.Frames, frame)
	if len(st.flow.Frames) >= t.cfg.MaxFrames {
		st.flow.EndReason = connection.EndMaxFrames
		flushed = append(flushed, st.flow)
		delete(t.flows, key)
	}
	return flushed
}

// Expire returns flows idle longer than Config.Idle.
func (t *Tracker) Expire(now time.Time) []Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	var flushed []Flow
	for key, st := range t.flows {
		if now.Sub(st.flow.LastSeen) >= t.cfg.Idle {
			st.flow.EndReason = connection.EndTimeout
			flushed = append(flushed, st.flow)
			delete(t.flows, key)
		}
	}
	return flushed
}

// Close flushes every live flow with endReason handler_close.
func (t *Tracker) Close() []Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	flushed := make([]Flow, 0, len(t.flows))
	for key, st := range t.flows {
		st.flow.EndReason = connection.EndHandlerClose
		flushed = append(flushed, st.flow)
		delete(t.flows, key)
	}
	return flushed
}

func (t *Tracker) evictLRULocked(now time.Time) *Flow {
	var oldestKey string
	var oldest *flowState
	for key, st := range t.flows {
		if oldest == nil || st.flow.LastSeen.Before(oldest.flow.LastSeen) {
			oldestKey = key
			oldest = st
		}
	}
	if oldest == nil {
		return nil
	}
	oldest.flow.EndReason = connection.EndEvicted
	// Touch so a caller that compares times sees eviction happened at now.
	_ = now
	out := oldest.flow
	delete(t.flows, oldestKey)
	return &out
}

func flowKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil {
		src = srcIP
	}
	if dst == nil {
		dst = dstIP
	}
	b := make([]byte, 0, 4+2+4+2)
	b = append(b, src...)
	b = append(b, byte(srcPort>>8), byte(srcPort))
	b = append(b, dst...)
	b = append(b, byte(dstPort>>8), byte(dstPort))
	return string(b)
}
