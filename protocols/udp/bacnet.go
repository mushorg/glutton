package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/bacnet"
)

// maxBACnetPayload is the largest BACnet/IP datagram (1476-byte APDU plus
// headers) with some slack.
const maxBACnetPayload = 1536

type parsedBACnet struct {
	Direction    string `json:"direction,omitempty"`
	Command      string `json:"command,omitempty"`
	BVLCFunction string `json:"bvlc_function,omitempty"`
	InvokeID     *int   `json:"invoke_id,omitempty"`
	Path         string `json:"path,omitempty"`
	Property     string `json:"property,omitempty"`
	ArrayIndex   *int   `json:"array_index,omitempty"`
	LowLimit     *int   `json:"low_limit,omitempty"`
	HighLimit    *int   `json:"high_limit,omitempty"`
	Password     string `json:"password,omitempty"`
	Status       string `json:"status,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
}

func intPtr[T uint32 | byte](v *T) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}

// HandleBACnet parses a BACnet/IP datagram and answers as one building
// controller with a stable per-sensor identity: Who-Is gets I-Am,
// ReadProperty on the device object gets a ReadProperty-ACK, writes and device
// control get an Error, other confirmed services a Reject. Replies go to the
// datagram source only.
func HandleBACnet(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxBACnetPayload))
	copy(payload, data[:len(payload)])

	events := []parsedBACnet{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("bacnet", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedBACnet](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "bacnet"), producer.ErrAttr(err))
		}
	}()

	frame := parsedBACnet{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxBACnetPayload,
	}
	msg, err := bacnet.Parse(payload)
	if msg != nil {
		frame.BVLCFunction = msg.FunctionName()
		frame.Command = msg.Command()
		if msg.HasAPDU && msg.PDUType == bacnet.PDUConfirmed {
			frame.InvokeID = intPtr(&msg.InvokeID)
		}
		if msg.Object != nil {
			frame.Path = msg.Object.String()
		}
		if msg.Property != nil {
			frame.Property = bacnet.PropertyName(*msg.Property)
		}
		frame.ArrayIndex = intPtr(msg.ArrayIndex)
		frame.LowLimit = intPtr(msg.LowLimit)
		frame.HighLimit = intPtr(msg.HighLimit)
		frame.Password = msg.Password
	}
	if err != nil || frame.Truncated {
		events = append(events, frame)
		logger.Debug("Failed to parse BACnet datagram", slog.String("protocol", "bacnet"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}
	events = append(events, frame)

	logger.Info("BACnet request received",
		slog.String("handler", "bacnet"),
		slog.String("protocol", "bacnet"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	reply := bacnet.Respond(msg, bacnet.DeviceFor([]byte(dstAddr.IP.String())))
	if reply == nil {
		return nil
	}
	events = append(events, parsedBACnet{
		Direction: "write",
		Command:   frame.Command,
		InvokeID:  frame.InvokeID,
		Path:      frame.Path,
		Property:  frame.Property,
		Status:    reply.Status,
		Payload:   reply.Payload,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, reply.Payload); err != nil {
		logger.Error("Failed to send BACnet reply", slog.String("protocol", "bacnet"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
