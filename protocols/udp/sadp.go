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
	"github.com/mushorg/glutton/protocols/udp/sadp"
)

const maxSADPPayload = 2048

// sadpNow sets the BootTime in replies; tests replace it.
var sadpNow = time.Now

type parsedSADP struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // lower-cased <Types> (inquiry, activate, ...)
	UUID      string `json:"uuid,omitempty"`
	Password  string `json:"password,omitempty"`
	Status    string `json:"status,omitempty"` // write: ProbeMatch
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// HandleSADP answers Hikvision SADP discovery on udp/37020: an "inquiry"
// <Probe> gets a <ProbeMatch> describing an activated IP camera. Other probe
// types (activate, modify, reset) are recorded only.
func HandleSADP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSADPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSADP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("sadp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSADP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sadp"), producer.ErrAttr(err))
		}
	}()

	req := sadp.Parse(payload)
	cmd := req.Command()
	events = append(events, parsedSADP{
		Direction: "read",
		Command:   cmd,
		UUID:      req.Uuid,
		Password:  req.Password,
		Payload:   payload,
		Truncated: len(data) > maxSADPPayload,
	})

	logger.Info("SADP request received",
		slog.String("handler", "sadp"),
		slog.String("protocol", "sadp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", cmd),
	)

	if cmd != sadp.TypeInquiry || !sadp.LooksLikeProbe(payload) {
		return nil
	}
	resp := sadp.BuildProbeMatch(req, sadp.DeviceFor([]byte(dstAddr.IP.String())), sadpNow())
	events = append(events, parsedSADP{
		Direction: "write",
		Command:   cmd,
		UUID:      req.Uuid,
		Status:    sadp.StatusProbeMatch,
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send SADP reply", slog.String("protocol", "sadp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
