package udp

import (
	"bytes"
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/rip"
)

// maxRIPPayload caps the stored datagram; a valid RIP message is at most 504
// bytes plus an authentication trailer.
const maxRIPPayload = 1024

type ripEntry struct {
	AFI      uint16 `json:"afi"`
	RouteTag uint16 `json:"route_tag,omitempty"`
	Address  string `json:"address"`
	Mask     string `json:"mask,omitempty"`
	NextHop  string `json:"next_hop,omitempty"`
	Metric   uint32 `json:"metric"`
}

type parsedRIP struct {
	Direction  string     `json:"direction,omitempty"`
	Command    string     `json:"command,omitempty"`
	Version    uint8      `json:"version,omitempty"`
	WholeTable bool       `json:"whole_table,omitempty"`
	Entries    []ripEntry `json:"entries,omitempty"`
	AuthType   string     `json:"auth_type,omitempty"`
	Password   string     `json:"password,omitempty"`
	KeyID      uint8      `json:"key_id,omitempty"`
	Sequence   uint32     `json:"sequence,omitempty"`
	Status     string     `json:"status,omitempty"`
	Payload    []byte     `json:"payload,omitempty"`
	Truncated  bool       `json:"truncated,omitempty"`
}

// HandleRIP parses a RIPv1/RIPv2 datagram. Requests are answered as a router
// with one directly connected network; the reply never has more entries than
// the request, so it is never larger. Responses (route injection) and other
// commands are recorded only.
func HandleRIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRIPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRIP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("rip", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRIP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rip"), producer.ErrAttr(err))
		}
	}()

	frame := parsedRIP{
		Direction: "read",
		Command:   "unknown",
		Payload:   payload,
		Truncated: len(data) > maxRIPPayload,
	}
	pkt, err := rip.Parse(payload)
	if pkt != nil {
		frame.Command = rip.CommandName(pkt.Command)
		frame.Version = pkt.Version
		frame.WholeTable = pkt.WholeTable()
		frame.Entries = ripEntries(pkt.Entries, pkt.Version)
		if a := pkt.Auth; a != nil {
			frame.AuthType = rip.AuthTypeName(a.Type)
			frame.Password = string(bytes.TrimRight(a.Password, "\x00"))
			frame.KeyID = a.KeyID
			frame.Sequence = a.Sequence
		}
	}
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse RIP datagram", slog.String("protocol", "rip"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("RIP datagram received",
		slog.String("handler", "rip"),
		slog.String("protocol", "rip"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	if frame.Truncated {
		return nil
	}
	resp := rip.Answer(pkt, rip.RouteFor([]byte(dstAddr.IP.String())))
	if resp == nil {
		return nil
	}
	reply, _ := rip.Parse(resp)
	events = append(events, parsedRIP{
		Direction: "write",
		Command:   "response",
		Version:   reply.Version,
		Entries:   ripEntries(reply.Entries, reply.Version),
		Status:    "response",
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send RIP reply", slog.String("protocol", "rip"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}

func ripEntries(entries []rip.Entry, version uint8) []ripEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]ripEntry, 0, len(entries))
	for _, e := range entries {
		r := ripEntry{AFI: e.AFI, Address: e.Address.String(), Metric: e.Metric}
		if version >= 2 {
			r.RouteTag = e.RouteTag
			r.Mask = e.Mask.String()
			r.NextHop = e.NextHop.String()
		}
		out = append(out, r)
	}
	return out
}
