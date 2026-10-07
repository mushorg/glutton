package tcp

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

const maxBufferSize = 1024

// sipMaxRead covers INVITEs with a full SDP offer (often > 1 KiB).
const sipMaxRead = 4096

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
	Variant   string `json:"variant,omitempty"` // response variant on writes
	Visit     int    `json:"visit,omitempty"`   // source's visit number on writes
}

// sipRecall remembers each source's last visit, shared with UDP SIP under
// the same "sip" key; tests swap it for a store with a fake clock.
var sipRecall = recall.Shared

type sipServer struct {
	events    []parsedSIP
	conn      net.Conn
	responder *sipproto.Responder
	srcIP     net.IP
	visit     int // 0 until the first request
	variant   sipproto.Variant
	store     *recall.Store // the store the visit began in
}

// begin picks the response variant once per connection: a source returning
// after recall.visit_gap gets the next sipproto.Variants entry.
func (s *sipServer) begin(logger interfaces.Logger) {
	if s.visit > 0 {
		return
	}
	s.store = sipRecall
	v := s.store.Begin("sip", s.srcIP, len(sipproto.Variants))
	s.visit, s.variant = v.Number, sipproto.Variants[v.Variant]
	if v.Started && v.Number > 1 {
		logger.Info("returning SIP source",
			slog.String("protocol", "sip"),
			slog.String("src_ip", s.srcIP.String()),
			slog.Int("visit", v.Number),
			slog.String("variant", s.variant.String()),
			slog.String("previous_variant", v.Previous.Variant),
			slog.Any("previous_commands", v.Previous.Commands),
		)
	}
}

// note stores what the source did on this connection.
func (s *sipServer) note() {
	if s.visit == 0 {
		return
	}
	s.store.Note("sip", s.srcIP, func(sum *recall.Summary) {
		sum.Variant = s.variant.String()
		sum.Events++
		for _, e := range s.events {
			if e.Direction != "read" {
				continue
			}
			sum.AddCommand(e.Command)
			sum.AddPath(e.Path)
			sum.AddUsername(e.Username)
			if e.UserAgent != "" {
				sum.UserAgent = e.UserAgent
			}
		}
	})
}

func remoteIP(conn net.Conn) net.IP {
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
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

func (s *sipServer) write(resp sip.Response) error {
	data := []byte(resp.String())
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame := sipDecoded("write", resp, data)
	frame.Variant, frame.Visit = s.variant.String(), s.visit
	s.events = append(s.events, frame)
	return nil
}

// HandleSIP takes a net.Conn and answers SIP like a misconfigured Asterisk PBX:
// OPTIONS and REGISTER get 200, INVITE is answered (100, 180, 200 with SDP).
func HandleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleSIP(ctx, conn, md, logger, h, sipproto.NewResponder())
}

func handleSIP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot, responder *sipproto.Responder) error {
	server := &sipServer{
		events:    []parsedSIP{},
		conn:      conn,
		responder: responder,
		srcIP:     remoteIP(conn),
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		server.note()
		if err := h.ProduceTCP("sip", conn, md, helpers.FirstOrEmpty[parsedSIP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SIP connection", slog.String("protocol", "sip"), producer.ErrAttr(err))
		}
	}()

	buffer := make([]byte, sipMaxRead)
	pp := parser.NewPacketParser(log.NewDefaultLogrusLogger())

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "sip"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}

		payload := make([]byte, n)
		copy(payload, buffer[:n])
		// bare-LF lines are accepted; the header end is not guessed on a stream
		msg, err := pp.ParseMessage(sipproto.NormalizeHeaders(payload, false))
		if err != nil {
			server.events = append(server.events, sipDecoded("read", nil, payload))
			endReason = connection.EndReadError
			return err
		}

		server.events = append(server.events, sipDecoded("read", msg, payload))

		req, ok := msg.(sip.Request)
		if !ok {
			continue
		}
		logger.Info("handling SIP request", slog.String("protocol", "sip"), slog.String("method", string(req.Method())))
		server.begin(logger)
		for _, resp := range server.responder.Reply(req, conn.RemoteAddr(), server.variant) {
			if err := server.write(resp); err != nil {
				logger.Error("Failed to write SIP reply", slog.String("protocol", "sip"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return err
			}
		}
	}
	return nil
}
