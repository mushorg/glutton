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
	"github.com/mushorg/glutton/protocols/udp/wsd"
)

const (
	maxWSDPayload = 4096
	// A ProbeMatches reply is larger than the probe, so answer each source at
	// most once per wsdReplyInterval and never send more than wsdMaxAmplification
	// times the request, so the sensor is not a useful reflector for spoofed
	// traffic.
	wsdReplyInterval    = time.Minute
	wsdMaxAmplification = 4
	maxWSDSources       = 4096
)

// wsdNow is the limiter clock; tests replace it.
var wsdNow = time.Now

type parsedWSD struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	Types     string `json:"types,omitempty"`
	Scopes    string `json:"scopes,omitempty"`
	Address   string `json:"address,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type wsdLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var wsdReplies = &wsdLimiter{last: map[string]time.Time{}}

// allow reports whether ip may get a reply now and records it if so.
func (l *wsdLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[ip]; ok && now.Sub(t) < wsdReplyInterval {
		return false
	}
	if len(l.last) >= maxWSDSources {
		for k, t := range l.last {
			if now.Sub(t) >= wsdReplyInterval {
				delete(l.last, k)
			}
		}
		if len(l.last) >= maxWSDSources {
			return false
		}
	}
	l.last[ip] = now
	return true
}

// HandleWSDiscovery parses a WS-Discovery SOAP-over-UDP datagram. A Probe for
// a plain device (or any type) gets a ProbeMatches, and a Resolve for the fake
// device address gets a ResolveMatches, both from a stable per-sensor device
// identity. Other actions (Hello, Bye, typed probes) are recorded only.
func HandleWSDiscovery(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxWSDPayload))
	copy(payload, data[:len(payload)])

	events := []parsedWSD{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("wsdiscovery", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedWSD](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "wsdiscovery"), producer.ErrAttr(err))
		}
	}()

	frame := parsedWSD{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxWSDPayload,
	}
	req, err := wsd.Parse(payload)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse WS-Discovery message", slog.String("protocol", "wsdiscovery"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = req.Command
	frame.MessageID = req.MessageID
	frame.Types = req.Types
	frame.Scopes = req.Scopes
	frame.Address = req.Address
	events = append(events, frame)

	logger.Info("WS-Discovery message received",
		slog.String("handler", "wsdiscovery"),
		slog.String("protocol", "wsdiscovery"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	resp, status := wsd.BuildMatches(req, dstAddr.IP.String())
	if resp == nil || len(resp) > wsdMaxAmplification*len(payload) {
		return nil
	}
	if !wsdReplies.allow(srcAddr.IP.String(), wsdNow()) {
		logger.Debug("WS-Discovery reply rate limited", slog.String("protocol", "wsdiscovery"), slog.String("src_ip", srcAddr.IP.String()))
		return nil
	}
	events = append(events, parsedWSD{
		Direction: "write",
		Command:   req.Command,
		Status:    status,
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send WS-Discovery reply", slog.String("protocol", "wsdiscovery"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
