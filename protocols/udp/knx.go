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
	"github.com/mushorg/glutton/protocols/udp/knx"
)

const (
	maxKNXPayload = 1024
	// Replies are 5x the size of a discovery probe; answer each source at
	// most once per knxReplyInterval so the sensor is no useful reflector.
	knxReplyInterval = time.Minute
	maxKNXSources    = 4096
)

// knxNow is the limiter clock; tests replace it.
var knxNow = time.Now

type parsedKNX struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	ServiceType string `json:"service_type,omitempty"`
	HPAIIP      string `json:"hpai_ip,omitempty"`
	HPAIPort    uint16 `json:"hpai_port,omitempty"`
	Status      string `json:"status,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

type knxLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var knxReplies = &knxLimiter{last: map[string]time.Time{}}

// allow reports whether ip may get a reply now and records it if so.
func (l *knxLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[ip]; ok && now.Sub(t) < knxReplyInterval {
		return false
	}
	if len(l.last) >= maxKNXSources {
		for k, t := range l.last {
			if now.Sub(t) >= knxReplyInterval {
				delete(l.last, k)
			}
		}
		if len(l.last) >= maxKNXSources {
			return false
		}
	}
	l.last[ip] = now
	return true
}

// HandleKNX parses a KNXnet/IP datagram. DESCRIPTION_REQUEST and
// SEARCH_REQUEST get a reply from a stable per-sensor gateway identity,
// CONNECT_REQUEST gets an error stub; the rest is recorded only. Replies go to
// the datagram's source address, never to the address in the request's HPAI.
func HandleKNX(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxKNXPayload))
	copy(payload, data[:len(payload)])

	events := []parsedKNX{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("knx", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedKNX](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "knx"), producer.ErrAttr(err))
		}
	}()

	frame := parsedKNX{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxKNXPayload,
	}
	req, err := knx.Parse(payload)
	if req != nil {
		frame.ServiceType = knx.ServiceTypeString(req.ServiceType)
		if req.HPAI != nil {
			frame.HPAIIP = req.HPAI.IP.String()
			frame.HPAIPort = req.HPAI.Port
		}
	}
	if err != nil {
		// A length mismatch or bad HPAI is not a usable request.
		events = append(events, frame)
		logger.Debug("Failed to parse KNX request", slog.String("protocol", "knx"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = req.Command()
	events = append(events, frame)

	logger.Info("KNX request received",
		slog.String("handler", "knx"),
		slog.String("protocol", "knx"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	var resp []byte
	status := ""
	switch req.ServiceType {
	case knx.DescriptionRequest, knx.SearchRequest:
		if !knxReplies.allow(srcAddr.IP.String(), knxNow()) {
			logger.Debug("KNX reply rate limited", slog.String("protocol", "knx"), slog.String("src_ip", srcAddr.IP.String()))
			return nil
		}
		dev := knx.DeviceFor([]byte(dstAddr.IP.String()))
		if req.ServiceType == knx.DescriptionRequest {
			resp, status = knx.BuildDescriptionResponse(dev), "DESCRIPTION_RESPONSE"
		} else {
			resp, status = knx.BuildSearchResponse(dev, dstAddr.IP, uint16(dstAddr.Port)), "SEARCH_RESPONSE"
		}
	case knx.ConnectRequest:
		if !knxReplies.allow(srcAddr.IP.String(), knxNow()) {
			logger.Debug("KNX reply rate limited", slog.String("protocol", "knx"), slog.String("src_ip", srcAddr.IP.String()))
			return nil
		}
		resp, status = knx.BuildConnectError(), knx.StatusNoMoreConnectionsName
	default:
		return nil
	}

	events = append(events, parsedKNX{
		Direction:   "write",
		Command:     frame.Command,
		ServiceType: knx.ServiceTypeString(binaryServiceType(resp)),
		Status:      status,
		Payload:     resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send KNX reply", slog.String("protocol", "knx"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}

func binaryServiceType(b []byte) uint16 { return uint16(b[2])<<8 | uint16(b[3]) }
