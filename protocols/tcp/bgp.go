package tcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/bgp"
)

const (
	// bgpMaxMessages bounds the messages read on one connection.
	bgpMaxMessages = 32
	// bgpLocalAS is the private AS the honeypot claims in its OPEN.
	bgpLocalAS = 65001
	// bgpHoldTime is the hold time offered in the OPEN (common router default).
	bgpHoldTime = 180
)

// bgpFallbackRouterID is the BGP Identifier used when the connection's local
// address is not a usable IPv4 address.
var bgpFallbackRouterID = [4]byte{10, 0, 0, 1}

type parsedBGP struct {
	Direction    string            `json:"direction,omitempty"`
	Header       bgp.Header        `json:"header,omitempty"`
	Command      string            `json:"command,omitempty"` // OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH, type-N
	Open         *bgp.Open         `json:"open,omitempty"`
	Notification *bgp.Notification `json:"notification,omitempty"`
	Status       string            `json:"status,omitempty"` // write: open, keepalive, notification
	Payload      []byte            `json:"payload,omitempty"`
}

type bgpServer struct {
	events   []parsedBGP
	conn     net.Conn
	routerID [4]byte
}

func (s *bgpServer) write(frame parsedBGP) error {
	if _, err := s.conn.Write(frame.Payload); err != nil {
		return err
	}
	frame.Direction = "write"
	if h, err := bgp.ParseHeader(frame.Payload); err == nil {
		frame.Header = h
		frame.Command = bgp.TypeName(h.Type)
	}
	s.events = append(s.events, frame)
	return nil
}

func (s *bgpServer) writeOpen() error {
	return s.write(parsedBGP{Status: "open", Payload: bgp.BuildOpen(bgpLocalAS, bgpHoldTime, s.routerID)})
}

func (s *bgpServer) writeKeepalive() error {
	return s.write(parsedBGP{Status: "keepalive", Payload: bgp.BuildKeepalive()})
}

func (s *bgpServer) writeNotification(code, subcode uint8, data []byte) error {
	return s.write(parsedBGP{
		Status:       "notification",
		Notification: &bgp.Notification{Code: code, Subcode: subcode, Data: data},
		Payload:      bgp.BuildNotification(code, subcode, data),
	})
}

// bgpRouterID uses the local IPv4 address (the address the scanner dialed)
// as the BGP Identifier, as routers usually do, and falls back otherwise.
func bgpRouterID(conn net.Conn) [4]byte {
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := addr.IP.To4(); ip4 != nil && !ip4.IsUnspecified() && !ip4.IsLoopback() {
			return [4]byte(ip4)
		}
	}
	return bgpFallbackRouterID
}

// HandleBGP takes a net.Conn and speaks the BGP-4 session opening on tcp/179:
// a valid OPEN is answered with OPEN and KEEPALIVE, KEEPALIVEs are echoed, and
// malformed or out-of-order messages get a NOTIFICATION and a close. No
// routes are ever advertised or processed.
func HandleBGP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &bgpServer{events: []parsedBGP{}, conn: conn, routerID: bgpRouterID(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("bgp", conn, md, helpers.FirstOrEmpty[parsedBGP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "bgp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close BGP connection", slog.String("protocol", "bgp"), producer.ErrAttr(err))
		}
	}()

	// notify sends a NOTIFICATION; the session always ends after one.
	notify := func(code, subcode uint8, data []byte) error {
		if err := server.writeNotification(code, subcode, data); err != nil {
			logger.Debug("Failed to write BGP notification", slog.String("protocol", "bgp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
		}
		return nil
	}

	opened := false
	for i := 0; i < bgpMaxMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "bgp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		hdr, raw, err := bgp.ReadMessage(conn)
		if len(raw) > 0 {
			frame := parsedBGP{Direction: "read", Payload: raw}
			if len(raw) >= bgp.HeaderLen && err == nil {
				frame.Header = hdr
				frame.Command = bgp.TypeName(hdr.Type)
			}
			server.events = append(server.events, frame)
		}
		if err != nil {
			var headerErr *bgp.HeaderError
			if errors.As(err, &headerErr) {
				logger.Debug("Invalid BGP header", slog.String("protocol", "bgp"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return notify(bgp.ErrCodeHeader, headerErr.Subcode, headerErr.Data)
			}
			logger.Debug("Failed to read data", slog.String("protocol", "bgp"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		frame := &server.events[len(server.events)-1]
		body := raw[bgp.HeaderLen:]

		switch hdr.Type {
		case bgp.TypeOpen:
			open, perr := bgp.ParseOpen(body)
			frame.Open = &open
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("BGP OPEN received",
				slog.String("handler", "bgp"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.Int("as", int(open.AS)),
				slog.String("bgp_id", open.BGPID),
			)
			switch {
			case opened:
				return notify(bgp.ErrCodeFSM, 0, nil)
			case perr != nil:
				return notify(bgp.ErrCodeOpen, 0, nil)
			case open.Version != bgp.Version:
				return notify(bgp.ErrCodeOpen, bgp.SubUnsupportedVersion, []byte{0, bgp.Version})
			case open.HoldTime == 1 || open.HoldTime == 2:
				return notify(bgp.ErrCodeOpen, bgp.SubUnacceptableHoldTime, nil)
			}
			opened = true
			if err := server.writeOpen(); err != nil {
				logger.Debug("Failed to write BGP OPEN", slog.String("protocol", "bgp"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
			if err := server.writeKeepalive(); err != nil {
				logger.Debug("Failed to write BGP KEEPALIVE", slog.String("protocol", "bgp"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		case bgp.TypeNotification:
			if n, ok := bgp.ParseNotification(body); ok {
				frame.Notification = &n
			}
			return nil
		case bgp.TypeKeepalive:
			if !opened {
				return notify(bgp.ErrCodeFSM, 0, nil)
			}
			if err := server.writeKeepalive(); err != nil {
				logger.Debug("Failed to write BGP KEEPALIVE", slog.String("protocol", "bgp"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		default: // UPDATE, ROUTE-REFRESH: recorded, never acted on
			if !opened {
				return notify(bgp.ErrCodeFSM, 0, nil)
			}
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
