package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/guard"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/tftp"
)

// maxTFTPPayload caps the stored datagram; request fields are capped by the
// tftp package.
const maxTFTPPayload = 1024

// tftpGuard is a TFTP-only reply budget charged before the global
// udp_reply_limit, so a flood of (possibly spoofed) requests cannot pull more
// than a handful of replies per source or a bounded rate from all sources
// together. A real client sends one request per transfer, so the per-source
// burst is small. It is a variable so tests can swap it.
var tftpGuard = guard.New(tftpGuardConfig())

func tftpGuardConfig() guard.Config {
	return guard.Config{
		Enabled: true,
		// Replies are never larger than a request (at most maxTFTPPayload), so
		// the byte burst must stay above that or a reply would never be sent.
		SourceRate:         256,
		SourceBurst:        2 * maxTFTPPayload,
		GlobalRate:         16 << 10,
		GlobalBurst:        128 << 10,
		SourceRequestRate:  1,
		SourceRequestBurst: 4,
		GlobalRequestRate:  256,
		GlobalRequestBurst: 512,
		MaxSources:         guard.DefaultMaxSources,
	}
}

type parsedTFTP struct {
	Direction string        `json:"direction,omitempty"`
	Command   string        `json:"command,omitempty"`
	Path      string        `json:"path,omitempty"`
	Mode      string        `json:"mode,omitempty"`
	Options   []tftp.Option `json:"options,omitempty"`
	Status    string        `json:"status,omitempty"`
	Payload   []byte        `json:"payload,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

// HandleTFTP parses a TFTP RRQ/WRQ. A read that carries recognised RFC 2347
// options is answered with an OACK; any other read gets file not found, and a
// write gets access violation. No file is ever served or accepted. Every reply
// is fitted so it is never larger than the request.
func HandleTFTP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxTFTPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedTFTP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("tftp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedTFTP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "tftp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedTFTP{Direction: "read", Command: "unknown", Payload: payload, Truncated: len(data) > maxTFTPPayload}
	req, err := tftp.Parse(payload)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse TFTP datagram", slog.String("protocol", "tftp"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = tftp.OpcodeName(req.Opcode)
	frame.Path = req.Filename
	frame.Mode = req.Mode
	frame.Options = req.Options
	events = append(events, frame)

	logger.Info("TFTP request received",
		slog.String("handler", "tftp"),
		slog.String("protocol", "tftp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
		slog.String("path", frame.Path),
	)

	var reply parsedTFTP
	if req.Opcode == tftp.OpRRQ {
		if resp, acked := tftp.OACKFitting(tftp.Negotiate(req.Filename, req.Options), len(data)); resp != nil {
			reply = parsedTFTP{Direction: "write", Command: "OACK", Status: "oack", Options: acked, Payload: resp}
		}
	}
	if reply.Command == "" {
		code, msg, status := tftp.ErrFileNotFound, "File not found", "file_not_found"
		if req.Opcode == tftp.OpWRQ {
			code, msg, status = tftp.ErrAccessViolation, "Access violation", "access_violation"
		}
		reply = parsedTFTP{Direction: "write", Command: "ERROR", Status: status, Payload: tftp.ErrorFitting(code, msg, len(data))}
	}
	resp := reply.Payload
	events = append(events, reply)
	// Like udp_reply_limit, a refused reply stays in the event as a write
	// frame but is not sent.
	if d := tftpGuard.Allow(srcAddr.IP, len(resp)); !d.Allowed {
		if d.First {
			logger.Warn("Dropping TFTP replies over the burst budget",
				slog.String("protocol", "tftp"),
				slog.String("limit", string(d.Limit)),
				slog.String("src_ip", srcAddr.IP.String()),
				slog.Int("bytes", len(resp)))
		}
		return nil
	}
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send TFTP reply", slog.String("protocol", "tftp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
