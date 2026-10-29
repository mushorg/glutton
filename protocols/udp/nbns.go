package udp

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/nbns"
)

const maxNBNSPayload = 512

// nbnsNames is the node-status table. The names match the SMB target
// (smbTargetName in protocols/tcp/smb.go).
var nbnsNames = []nbns.NodeName{
	{Name: "SERVER", Suffix: 0x00},
	{Name: "SERVER", Suffix: 0x20},
	{Name: "WORKGROUP", Suffix: 0x00, Group: true},
}

type parsedNBNS struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // NBSTAT, NB, REGISTRATION, RELEASE, UNKNOWN
	Path      string `json:"path,omitempty"`    // decoded name and suffix, e.g. "*<00>"
	TXID      uint16 `json:"txid,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// HandleNBNS answers NetBIOS name service queries on udp/137. An NBSTAT for
// "*" or SERVER and an NB query for SERVER get a reply; registrations,
// releases, responses, and anything else are recorded only. Replies go
// through ReplyUDP so the UDP reply budget applies. The node-status table
// is three names, about four times a 50-byte query.
func HandleNBNS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxNBNSPayload))
	copy(payload, data[:len(payload)])
	truncated := len(data) > maxNBNSPayload

	events := []parsedNBNS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("nbns", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedNBNS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "nbns"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}
	msg, err := nbns.Parse(payload)
	frame := parsedNBNS{Direction: "read", Command: "UNKNOWN", Payload: payload, Truncated: truncated}
	if len(payload) >= 12 {
		frame.TXID = msg.TXID
		frame.Command = msg.Command()
		frame.Path = msg.Path()
	}
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse NBNS message", slog.String("protocol", "nbns"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	logger.Info("NBNS packet received",
		slog.String("handler", "nbns"),
		slog.String("protocol", "nbns"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
		slog.String("path", frame.Path),
	)
	if msg.Response() || broadcastDst(dstAddr) {
		return nil
	}
	resp, status := nbnsReply(msg, dstAddr)
	if resp == nil {
		return nil
	}
	events = append(events, parsedNBNS{
		Direction: "write",
		Command:   frame.Command,
		Path:      frame.Path,
		TXID:      msg.TXID,
		Status:    status,
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send NBNS reply", slog.String("protocol", "nbns"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}

func nbnsReply(msg nbns.Message, dst *net.UDPAddr) ([]byte, string) {
	switch msg.Command() {
	case "NBSTAT":
		if msg.Name != "*" && !strings.EqualFold(msg.Name, "SERVER") {
			return nil, ""
		}
		return nbns.BuildNodeStatus(msg.TXID, msg.EncodedName, nbnsNames, sensorMAC(dst.IP)), "NBSTAT"
	case "NB":
		if !strings.EqualFold(msg.Name, "SERVER") {
			return nil, ""
		}
		return nbns.BuildNameQuery(msg.TXID, msg.EncodedName, dst.IP), "NB"
	default:
		return nil, ""
	}
}

// sensorMAC is a locally administered address stable for the destination
// the packet arrived on, which is the sensor's address.
func sensorMAC(ip net.IP) [6]byte {
	v4 := ip.To4()
	if v4 == nil {
		return [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	}
	return [6]byte{0x02, 0x00, v4[0], v4[1], v4[2], v4[3]}
}

func broadcastDst(addr *net.UDPAddr) bool {
	if addr == nil || addr.IP == nil {
		return false
	}
	if addr.IP.IsMulticast() {
		return true
	}
	v4 := addr.IP.To4()
	return v4 != nil && v4.Equal(net.IPv4bcast)
}
