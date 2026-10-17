package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/tftp"
)

// maxTFTPPayload caps the stored datagram; request fields are capped by the
// tftp package.
const maxTFTPPayload = 1024

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

// HandleTFTP parses a TFTP RRQ/WRQ and answers with an ERROR packet (file not
// found for reads, access violation for writes). No file is ever served or
// accepted. The reply is trimmed so it is never larger than the request.
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

	code, msg, status := tftp.ErrFileNotFound, "File not found", "file_not_found"
	if req.Opcode == tftp.OpWRQ {
		code, msg, status = tftp.ErrAccessViolation, "Access violation", "access_violation"
	}
	resp := tftp.ErrorFitting(code, msg, len(data))
	events = append(events, parsedTFTP{Direction: "write", Command: "ERROR", Status: status, Payload: resp})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send TFTP reply", slog.String("protocol", "tftp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
