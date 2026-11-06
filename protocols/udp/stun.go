package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/stun"
)

const maxSTUNPayload = 1024

type parsedSTUN struct {
	Direction     string   `json:"direction,omitempty"`
	Command       string   `json:"command,omitempty"`
	Status        string   `json:"status,omitempty"`
	TransactionID string   `json:"transaction_id,omitempty"`
	Attributes    []string `json:"attributes,omitempty"`
	Software      string   `json:"software,omitempty"`
	Payload       []byte   `json:"payload,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
}

// HandleSTUN records a STUN message and answers a Binding Request with a
// Binding Success Response carrying the sender's XOR-MAPPED-ADDRESS. Other
// methods (TURN allocate, indications, responses) are recorded only.
func HandleSTUN(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSTUNPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSTUN{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("stun", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSTUN](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "stun"), producer.ErrAttr(err))
		}
	}()

	frame := parsedSTUN{
		Direction: "read",
		Command:   "unknown",
		Payload:   payload,
		Truncated: len(data) > maxSTUNPayload,
	}
	// parse the full datagram: the length field must match it
	m, err := stun.Parse(data)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse STUN message", slog.String("protocol", "stun"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}
	frame.Command = m.Command()
	frame.TransactionID = m.TxID()
	frame.Attributes = m.Attributes
	frame.Software = m.Software
	events = append(events, frame)

	logger.Info("STUN message received",
		slog.String("handler", "stun"),
		slog.String("protocol", "stun"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	if m.Type != stun.TypeBindingRequest {
		return nil
	}
	resp := stun.BuildBindingSuccess(m, srcAddr)
	if resp == nil {
		return nil
	}
	events = append(events, parsedSTUN{
		Direction:     "write",
		Command:       stun.TypeName(stun.TypeBindingSuccess),
		Status:        "success",
		TransactionID: frame.TransactionID,
		Attributes:    []string{"xor-mapped-address"},
		Payload:       resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send STUN reply", slog.String("protocol", "stun"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
