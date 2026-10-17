package udp

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/dht"
)

const maxDHTPayload = 1024

// dhtOurID is the node id advertised in replies. Tests replace it.
var dhtOurID = randomDHTNodeID()

func randomDHTNodeID() [dht.NodeIDLen]byte {
	var id [dht.NodeIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		for i := range id {
			id[i] = byte(i + 1)
		}
	}
	return id
}

type parsedDHT struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Status      string `json:"status,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	Target      string `json:"target,omitempty"`
	InfoHash    string `json:"info_hash,omitempty"`
	Want        string `json:"want,omitempty"`
	Transaction string `json:"transaction,omitempty"`
	Port        int    `json:"port,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// HandleDHT parses a BitTorrent DHT (BEP 5) query and answers with a valid
// response that is never larger than the request. The sensor does not join a
// swarm or dial peers.
func HandleDHT(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxDHTPayload))
	copy(payload, data[:len(payload)])

	events := []parsedDHT{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("dht", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedDHT](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dht"), producer.ErrAttr(err))
		}
	}()

	frame := parsedDHT{
		Direction: "read",
		Command:   "unknown",
		Payload:   payload,
		Truncated: len(data) > maxDHTPayload,
	}
	q, err := dht.ParseQuery(payload)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse DHT datagram", slog.String("protocol", "dht"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = q.Method
	frame.NodeID = dht.Hex(q.ID)
	frame.Target = dht.Hex(q.Target)
	frame.InfoHash = dht.Hex(q.InfoHash)
	frame.Want = strings.Join(q.Want, ",")
	frame.Transaction = dht.Hex(q.Transaction)
	frame.Port = q.Port
	events = append(events, frame)

	logger.Info("DHT query received",
		slog.String("handler", "dht"),
		slog.String("protocol", "dht"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	resp := dht.BuildResponse(q, dhtOurID, dstAddr, len(data))
	if resp == nil {
		return nil
	}
	events = append(events, parsedDHT{
		Direction:   "write",
		Command:     q.Method,
		Status:      "response",
		NodeID:      dht.Hex(dhtOurID[:]),
		Transaction: dht.Hex(q.Transaction),
		Payload:     resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send DHT reply", slog.String("protocol", "dht"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
