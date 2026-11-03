package udp

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/ntp"
)

const maxNTPPayload = 1024

// ntpNow and ntpRefID are replaced in tests.
var (
	ntpNow   = time.Now
	ntpRefID = [4]byte{192, 53, 103, 108}
)

type parsedNTP struct {
	Direction      string `json:"direction,omitempty"`
	Command        string `json:"command,omitempty"`
	Status         string `json:"status,omitempty"`
	Version        int    `json:"version,omitempty"`
	Mode           int    `json:"mode,omitempty"`
	Implementation int    `json:"implementation,omitempty"`
	RequestCode    int    `json:"request_code,omitempty"`
	Opcode         int    `json:"opcode,omitempty"`
	Stratum        int    `json:"stratum,omitempty"`
	Payload        []byte `json:"payload,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
}

// HandleNTP parses an NTP datagram and answers it with a reply never larger
// than the request: a stratum 2 server packet for mode 3, a small error packet
// for mode 6/7 (so no monlist or readvar amplification). Anything else is only
// recorded.
func HandleNTP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxNTPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedNTP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("ntp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedNTP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ntp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedNTP{
		Direction: "read",
		Command:   "unknown",
		Payload:   payload,
		Truncated: len(data) > maxNTPPayload,
	}
	p, err := ntp.Parse(payload)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse NTP datagram", slog.String("protocol", "ntp"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = p.Command()
	frame.Version = p.Version
	frame.Mode = p.Mode
	switch p.Mode {
	case ntp.ModePrivate:
		frame.Implementation = p.Impl
		frame.RequestCode = p.ReqCode
	case ntp.ModeControl:
		frame.Opcode = p.Opcode
	default:
		frame.Stratum = p.Stratum
	}
	events = append(events, frame)

	logger.Info("NTP request received",
		slog.String("handler", "ntp"),
		slog.String("protocol", "ntp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	resp := ntp.BuildResponse(p, payload, ntpNow(), ntpRefID)
	if resp == nil || len(resp) > len(data) {
		return nil
	}
	status := "server"
	switch p.Mode {
	case ntp.ModePrivate, ntp.ModeControl:
		status = "error"
	}
	events = append(events, parsedNTP{
		Direction:      "write",
		Command:        frame.Command,
		Status:         status,
		Version:        int(resp[0] >> 3 & 7),
		Mode:           int(resp[0] & 7),
		Implementation: frame.Implementation,
		RequestCode:    frame.RequestCode,
		Opcode:         frame.Opcode,
		Payload:        resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send NTP reply", slog.String("protocol", "ntp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
