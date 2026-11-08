package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/pcanywhere"
)

const maxPCAnywherePayload = 1024

type parsedPCAnywhere struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // NQ (name query) or ST (status query)
	Status    string `json:"status,omitempty"`  // write: NR or available
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// pcAnywherePersona is the host the replies describe; tests may swap it.
var pcAnywherePersona = pcanywhere.DefaultPersona

// HandlePCAnywhere answers Symantec pcAnywhere UDP discovery on udp/5632:
// the "NQ" name query gets an "NR" host name reply and the "ST" status
// query reports an available host. Other datagrams are recorded only.
func HandlePCAnywhere(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxPCAnywherePayload))
	copy(payload, data[:len(payload)])

	events := []parsedPCAnywhere{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("pcanywhere", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedPCAnywhere](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "pcanywhere"), producer.ErrAttr(err))
		}
	}()

	cmd := pcanywhere.Command(payload)
	events = append(events, parsedPCAnywhere{
		Direction: "read",
		Command:   cmd,
		Payload:   payload,
		Truncated: len(data) > maxPCAnywherePayload,
	})

	logger.Info("pcanywhere request received",
		slog.String("handler", "pcanywhere"),
		slog.String("protocol", "pcanywhere"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", cmd),
	)

	body, status := pcanywhere.Reply(cmd, pcAnywherePersona)
	if body == nil {
		return nil
	}
	events = append(events, parsedPCAnywhere{Direction: "write", Command: cmd, Status: status, Payload: body})
	if err := h.ReplyUDP(srcAddr, dstAddr, body); err != nil {
		logger.Error("Failed to send pcanywhere reply", slog.String("protocol", "pcanywhere"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
