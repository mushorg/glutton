package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/dns"
)

// maxDNSMessages bounds the queries answered on one connection; resolvers
// reuse a TCP connection for a few queries, scanners send one.
const maxDNSMessages = 8

type parsedDNS struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	ID        uint16 `json:"id,omitempty"`        // DNS message ID
	Opcode    string `json:"opcode,omitempty"`    // non-QUERY opcodes only (iquery, status, notify, update, ...)
	Command   string `json:"command,omitempty"`   // query type (A, AAAA, ANY, AXFR, TYPE65280, ...)
	Class     string `json:"class,omitempty"`     // query class when not IN (CH for version.bind probes)
	Path      string `json:"path,omitempty"`      // query name
	Status    string `json:"status,omitempty"`    // response code on writes (REFUSED, FORMERR, ...)
	Payload   []byte `json:"payload,omitempty"`   // raw bytes as seen on the wire, length prefix included
	Truncated bool   `json:"truncated,omitempty"` // the client stopped before the announced message length
}

var dnsOpcodeNames = map[uint8]string{1: "iquery", 2: "status", 4: "notify", 5: "update"}

// readDNS reads one length-prefixed message. The returned frame bytes include
// the prefix; on a short body they hold whatever arrived and truncated is set,
// so a non-DNS client that announced a long "message" is still captured.
func readDNS(conn net.Conn) (frame []byte, truncated bool, err error) {
	var prefix [2]byte
	n, err := io.ReadFull(conn, prefix[:])
	if err != nil {
		return append([]byte(nil), prefix[:n]...), n > 0, err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	frame = make([]byte, 2+size)
	copy(frame, prefix[:])
	n, err = io.ReadFull(conn, frame[2:])
	if err != nil {
		return frame[:2+n], true, err
	}
	return frame, false, nil
}

// HandleDNS takes a net.Conn and answers DNS-over-TCP queries (RFC 7766) the
// way a non-recursive name server does: REFUSED for every real query (AXFR and
// recursion requests included), NOTIMP for other opcodes, FORMERR for a
// malformed question. Nothing is resolved or forwarded, and a reply is never
// larger than its query.
func HandleDNS(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedDNS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("dns", conn, md, helpers.FirstOrEmpty[parsedDNS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dns"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close DNS connection", slog.String("protocol", "dns"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxDNSMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "dns"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		frame, truncated, err := readDNS(conn)
		if len(frame) > 0 {
			events = append(events, parsedDNS{Direction: "read", Payload: frame, Truncated: truncated})
		}
		if err != nil {
			if err != io.EOF {
				logger.Debug("Failed to read data", slog.String("protocol", "dns"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}

		q, perr := dns.Parse(frame[2:])
		if perr == dns.ErrShort {
			// not enough for a header, so there is no ID to answer with
			logger.Debug("DNS message too short", slog.String("protocol", "dns"), slog.Int("bytes", len(frame)-2))
			return nil
		}
		read := &events[len(events)-1]
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

		logger.Info(
			"DNS query",
			slog.String("handler", "dns"),
			slog.String("protocol", "dns"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("command", read.Command),
			slog.String("path", read.Path),
		)

		// a message with QR set is a response, and answering it could start
		// a reflection loop with another server
		if q.Response {
			continue
		}
		rcode := dns.Refusal(q, perr)
		msg := dns.BuildResponse(q, rcode, perr)
		reply := make([]byte, 2+len(msg))
		binary.BigEndian.PutUint16(reply, uint16(len(msg)))
		copy(reply[2:], msg)
		if _, err := conn.Write(reply); err != nil {
			logger.Debug("Failed to write response", slog.String("protocol", "dns"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		events = append(events, parsedDNS{Direction: "write", ID: q.ID, Status: dns.RcodeName(rcode), Payload: reply})
	}
	endReason = connection.EndMaxFrames
	return nil
}
