package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/rtps"
)

const maxRTPSPayload = 1024

type parsedRTPS struct {
	Direction       string            `json:"direction,omitempty"`
	Command         string            `json:"command,omitempty"`
	Version         string            `json:"version,omitempty"`
	VendorID        string            `json:"vendor_id,omitempty"`
	Vendor          string            `json:"vendor,omitempty"`
	GUIDPrefix      string            `json:"guid_prefix,omitempty"`
	Submessages     []rtps.Submessage `json:"submessages,omitempty"`
	WriterEntityID  string            `json:"writer_entity_id,omitempty"`
	WriterSN        uint64            `json:"writer_sn,omitempty"`
	ParticipantGUID string            `json:"participant_guid,omitempty"`
	UserData        string            `json:"user_data,omitempty"`
	EntityName      string            `json:"entity_name,omitempty"`
	DomainID        *uint32           `json:"domain_id,omitempty"`
	Locators        []string          `json:"locators,omitempty"`
	VendorStrings   []string          `json:"vendor_strings,omitempty"`
	Payload         []byte            `json:"payload,omitempty"`
	Truncated       bool              `json:"truncated,omitempty"`
}

// HandleRTPS parses an RTPS (DDS) datagram, typically an SPDP participant
// announcement on udp/7400, and emits one producer event. It does not reply:
// answering discovery would make the sensor a DDS participant.
func HandleRTPS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRTPSPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRTPS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("rtps", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRTPS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rtps"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	pkt, err := rtps.Parse(payload)
	if err != nil {
		logger.Debug("RTPS packet was not fully parseable", slog.String("protocol", "rtps"), slog.Int("bytes", len(payload)), producer.ErrAttr(err))
	}
	command := pkt.Command
	if command == "" {
		command = "UNKNOWN"
	}
	events = append(events, parsedRTPS{
		Direction:       "read",
		Command:         command,
		Version:         pkt.Version,
		VendorID:        pkt.VendorID,
		Vendor:          pkt.Vendor,
		GUIDPrefix:      pkt.GUIDPrefix,
		Submessages:     pkt.Submessages,
		WriterEntityID:  pkt.WriterEntityID,
		WriterSN:        pkt.WriterSN,
		ParticipantGUID: pkt.ParticipantGUID,
		UserData:        pkt.UserData,
		EntityName:      pkt.EntityName,
		DomainID:        pkt.DomainID,
		Locators:        pkt.Locators,
		VendorStrings:   pkt.VendorStrings,
		Payload:         payload,
		Truncated:       len(data) > maxRTPSPayload,
	})

	logger.Info("RTPS UDP packet received",
		slog.String("handler", "rtps"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", command),
		slog.String("vendor_id", pkt.VendorID),
		slog.String("user_data", pkt.UserData),
	)
	return nil
}
