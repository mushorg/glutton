package udp

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/dns"
)

// maxDNSPayload caps the captured datagram; real queries are well below it
// (EDNS0 resolvers send a few hundred bytes at most).
const maxDNSPayload = 1232

// parsedDNS mirrors the decoded frame of the TCP dns handler so both
// transports produce the same shape; Payload carries no length prefix here.
type parsedDNS struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	ID        uint16 `json:"id,omitempty"`        // DNS message ID
	Opcode    string `json:"opcode,omitempty"`    // non-QUERY opcodes only (iquery, status, notify, update, ...)
	Command   string `json:"command,omitempty"`   // query type (A, AAAA, ANY, AXFR, TYPE65280, ...)
	Class     string `json:"class,omitempty"`     // query class when not IN (CH for version.bind probes)
	Path      string `json:"path,omitempty"`      // query name
	Status    string `json:"status,omitempty"`    // response code on writes (REFUSED, FORMERR, ...)
	Payload   []byte `json:"payload,omitempty"`   // raw datagram as seen on the wire
	Truncated bool   `json:"truncated,omitempty"` // the datagram exceeded maxDNSPayload
}

var dnsOpcodeNames = map[uint8]string{1: "iquery", 2: "status", 4: "notify", 5: "update"}

// HandleDNS answers a DNS query on udp/53 the way a non-recursive name server
// does: REFUSED for every real query (ANY and recursion requests included),
// NOTIMP for other opcodes, BADVERS for EDNS versions other than 0, FORMERR
// for a malformed question. Nothing is resolved or forwarded, no records are
// returned and the reply is never larger than the query, so the handler
// cannot be used for amplification. Replies go through ReplyUDP.
func HandleDNS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxDNSPayload))
	copy(payload, data[:len(payload)])

	events := []parsedDNS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("dns", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedDNS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dns"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}
	read := parsedDNS{Direction: "read", Payload: payload, Truncated: len(data) > maxDNSPayload}
	q, perr := dns.Parse(payload)
	if perr == dns.ErrShort {
		// not enough for a header, so there is no ID to answer with
		events = append(events, read)
		logger.Debug("DNS message too short", slog.String("protocol", "dns"), slog.Int("bytes", len(payload)))
		return nil
	}
	read.ID = q.ID
	if q.Opcode != 0 {
		read.Opcode = dnsOpcodeNames[q.Opcode]
		if read.Opcode == "" {
			read.Opcode = "opcode" + strconv.Itoa(int(q.Opcode))
		}
	}
	if perr == nil {
		read.Command, read.Path = dns.TypeName(q.Type), q.Name
		if q.Class != 1 {
			read.Class = dns.ClassName(q.Class)
		}
	}
	events = append(events, read)

	logger.Info(
		"DNS query",
		slog.String("handler", "dns"),
		slog.String("protocol", "dns"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", read.Command),
		slog.String("path", read.Path),
	)

	// a message with QR set is a response, and answering it could start a
	// reflection loop with another server
	if q.Response {
		return nil
	}
	rcode := dns.Refusal(q, perr)
	reply := dns.BuildResponse(q, rcode, perr)
	events = append(events, parsedDNS{Direction: "write", ID: q.ID, Status: dns.RcodeName(rcode), Payload: reply})
	if err := h.ReplyUDP(srcAddr, dstAddr, reply); err != nil {
		logger.Error("Failed to send DNS reply", slog.String("protocol", "dns"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
