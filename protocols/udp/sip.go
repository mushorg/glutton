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
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

// maxSIPPayload covers INVITEs with a full SDP offer (often > 1 KiB).
const maxSIPPayload = 4096

type parsedSIP struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // request method
	Path      string `json:"path,omitempty"`    // Request-URI
	Status    string `json:"status,omitempty"`  // response code on writes
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	UserAgent string `json:"user_agent,omitempty"` // User-Agent (reads) or Server (writes)
	Username  string `json:"username,omitempty"`   // digest Authorization username
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

func sipDecoded(direction string, msg sip.Message, payload []byte) parsedSIP {
	frame := parsedSIP{Direction: direction, Payload: payload}
	if msg == nil {
		return frame
	}
	info := sipproto.Describe(msg)
	frame.Command = info.Method
	frame.Path = info.URI
	if info.Status != 0 {
		frame.Status = strconv.Itoa(info.Status)
	}
	frame.From = info.From
	frame.To = info.To
	frame.CallID = info.CallID
	frame.UserAgent = info.UserAgent
	frame.Username = info.Username
	return frame
}

// sipResponder builds the UDP SIP replies; tests swap it for deterministic tags and nonces.
var sipResponder = sipproto.NewResponder()

// parseSIP parses one datagram, tolerating bare-LF lines. A complete
// datagram may also omit the empty line after the headers; a truncated one
// may not, as its end is not the end of the message. data is not modified.
func parseSIP(data []byte, complete bool) (sip.Message, error) {
	return parser.NewPacketParser(log.NewDefaultLogrusLogger()).ParseMessage(sipproto.NormalizeHeaders(data, complete))
}

// HandleSIP parses a UDP SIP datagram and answers it like a misconfigured
// Asterisk PBX (OPTIONS and REGISTER 200, INVITE 100/180 then 200 with SDP
// after a ringing delay; the first few INVITEs per source get 404).
// An INVITE opens a dialog keyed by source IP and Call-ID: later datagrams
// with that key (ACK, BYE, CANCEL, retransmits) join it, and the dialog is
// produced as one event when it ends (BYE or CANCEL answered, idle timeout,
// frame cap or table eviction). Any other datagram is one event of its own.
func HandleSIP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSIPPayload))
	copy(payload, data[:len(payload)])
	truncated := len(data) > maxSIPPayload

	if len(payload) == 0 {
		return handleSIPDatagram(srcAddr, dstAddr, nil, parsedSIP{}, nil, md, logger, h)
	}

	logger.Info("SIP UDP packet received",
		slog.String("handler", "sip"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
	)

	msg, err := parseSIP(payload, !truncated)
	frame := sipDecoded("read", msg, payload)
	frame.Truncated = truncated
	if err != nil {
		logger.Debug("Failed to parse SIP message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		return handleSIPDatagram(srcAddr, dstAddr, nil, frame, err, md, logger, h)
	}

	if frame.CallID != "" {
		key := sipDialogKey(srcAddr, frame.CallID)
		d := sipDialogs.get(key)
		if req, ok := msg.(sip.Request); ok && req.Method() == sip.INVITE && d == nil {
			var evicted *sipDialog
			d, evicted = sipDialogs.open(key, func() *sipDialog {
				d := newSIPDialog(ctx, key, sipDialogs, srcAddr, dstAddr, md, logger, h)
				d.reject = sipRejects.reject(srcAddr.IP.String(), sipNow(), sipRejectInvites())
				return d
			})
			if evicted != nil {
				evicted.finish(connection.EndEvicted)
			}
		}
		if d != nil {
			if handled, err := d.handle(msg, frame); handled {
				return err
			}
		}
	}
	return handleSIPDatagram(srcAddr, dstAddr, msg, frame, nil, md, logger, h)
}

// handleSIPDatagram answers a datagram outside any dialog and produces it as
// one event. parseErr is the parse failure for an unparsable datagram.
func handleSIPDatagram(srcAddr, dstAddr *net.UDPAddr, msg sip.Message, frame parsedSIP, parseErr error, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedSIP{}
	if frame.Payload != nil {
		events = append(events, frame)
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("sip", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSIP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	if parseErr != nil {
		endReason = connection.EndReadError
		return parseErr
	}
	req, ok := msg.(sip.Request)
	if !ok {
		return nil
	}
	logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))

	for _, resp := range sipResponder.Reply(req, srcAddr) {
		respBytes := []byte(resp.String())
		events = append(events, sipDecoded("write", resp, respBytes))
		if err := h.ReplyUDP(srcAddr, dstAddr, respBytes); err != nil {
			logger.Error("Failed to send SIP reply", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	return nil
}
