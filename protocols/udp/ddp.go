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
	"github.com/mushorg/glutton/protocols/udp/ddp"
)

const (
	maxDDPPayload = 1024
	// A search reply is ~3x the size of a SRCH probe, so answer each source
	// at most once per ddpReplyInterval to keep the sensor from being a
	// useful reflector for spoofed traffic.
	ddpReplyInterval = time.Minute
	maxDDPSources    = 4096
)

// ddpNow is the limiter clock; tests replace it.
var ddpNow = time.Now

type parsedDDP struct {
	Direction             string `json:"direction,omitempty"`
	Command               string `json:"command,omitempty"`
	Version               string `json:"version,omitempty"`
	ClientType            string `json:"client_type,omitempty"`
	UserCredentialPresent bool   `json:"user_credential_present,omitempty"`
	HostType              string `json:"host_type,omitempty"`
	Status                string `json:"status,omitempty"`
	Payload               []byte `json:"payload,omitempty"`
	Truncated             bool   `json:"truncated,omitempty"`
}

type ddpLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var ddpReplies = &ddpLimiter{last: map[string]time.Time{}}

// allow reports whether ip may get a reply now and records it if so.
func (l *ddpLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[ip]; ok && now.Sub(t) < ddpReplyInterval {
		return false
	}
	if len(l.last) >= maxDDPSources {
		for k, t := range l.last {
			if now.Sub(t) >= ddpReplyInterval {
				delete(l.last, k)
			}
		}
		if len(l.last) >= maxDDPSources {
			return false
		}
	}
	l.last[ip] = now
	return true
}

// HandleDDP parses a PlayStation Device Discovery Protocol datagram. SRCH gets
// a "620 Server Standby" reply from a stable per-sensor console identity;
// WAKEUP and LAUNCH are recorded only. The user-credential value is never
// stored, only whether one was sent.
func HandleDDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxDDPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedDDP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("ddp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedDDP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ddp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedDDP{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxDDPPayload,
	}
	req, err := ddp.Parse(payload)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse DDP request", slog.String("protocol", "ddp"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = req.Method
	frame.Version = req.Version()
	frame.ClientType = req.Headers[ddp.HeaderClientType]
	_, frame.UserCredentialPresent = req.Headers[ddp.HeaderUserCredential]
	events = append(events, frame)

	logger.Info("DDP request received",
		slog.String("handler", "ddp"),
		slog.String("protocol", "ddp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	if req.Method != ddp.MethodSearch {
		return nil
	}
	if !ddpReplies.allow(srcAddr.IP.String(), ddpNow()) {
		logger.Debug("DDP reply rate limited", slog.String("protocol", "ddp"), slog.String("src_ip", srcAddr.IP.String()))
		return nil
	}
	console := ddp.ConsoleFor([]byte(dstAddr.IP.String()), frame.Version)
	resp := ddp.BuildSearchResponse(console)
	events = append(events, parsedDDP{
		Direction: "write",
		Command:   req.Method,
		Version:   console.Version,
		HostType:  console.HostType,
		Status:    ddp.StatusStandby,
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send DDP reply", slog.String("protocol", "ddp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
