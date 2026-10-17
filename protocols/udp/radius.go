package udp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/radius"
)

const maxRADIUSPayload = 4096

type parsedRADIUS struct {
	Direction            string `json:"direction,omitempty"`             // "read" (from attacker) or "write" (from honeypot)
	Command              string `json:"command,omitempty"`               // Access-Request, Accounting-Request, ...; "malformed" for an unparseable datagram
	Identifier           int    `json:"identifier"`                      // request/response identifier
	Username             string `json:"username,omitempty"`              // User-Name
	Password             string `json:"password,omitempty"`              // User-Password, decrypted with a common shared secret
	PasswordHidden       string `json:"password_hidden,omitempty"`       // hex of the User-Password attribute as sent
	CHAPPassword         string `json:"chap_password,omitempty"`         // hex of the CHAP-Password attribute
	NASIP                string `json:"nas_ip,omitempty"`                // NAS-IP-Address
	NASIdentifier        string `json:"nas_identifier,omitempty"`        // NAS-Identifier
	CallingStationID     string `json:"calling_station_id,omitempty"`    // Calling-Station-Id
	CalledStationID      string `json:"called_station_id,omitempty"`     // Called-Station-Id
	MessageAuthenticator bool   `json:"message_authenticator,omitempty"` // client sent a Message-Authenticator
	Status               string `json:"status,omitempty"`                // write outcome: reject, accept, ok
	Payload              []byte `json:"payload,omitempty"`
	Truncated            bool   `json:"truncated,omitempty"`
}

// HandleRADIUS records RADIUS Access-Request, Accounting-Request and
// Status-Server datagrams (udp/1812, 1813) with their credentials and answers
// them with a bare 20-byte Access-Reject, Accounting-Response or Access-Accept
// so scanners confirm a RADIUS server and go on to guess. Other codes are
// recorded only. Replies go through ReplyUDP and are never larger than the
// request, so the sensor is no amplifier.
func HandleRADIUS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRADIUSPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRADIUS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("radius", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRADIUS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "radius"), producer.ErrAttr(err))
		}
	}()

	frame := parsedRADIUS{Direction: "read", Payload: payload, Truncated: len(data) > maxRADIUSPayload}
	pkt, err := radius.Parse(payload)
	if err != nil && pkt.Code == 0 && pkt.Length == 0 {
		frame.Command = "malformed"
		frame.Truncated = true
		events = append(events, frame)
		logger.Debug("Failed to parse RADIUS header", slog.String("protocol", "radius"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}
	frame.Command = radius.CodeName(pkt.Code)
	frame.Identifier = int(pkt.ID)
	if err != nil {
		// header was readable but the length or an attribute is inconsistent
		frame.Truncated = true
		logger.Debug("Failed to parse RADIUS packet", slog.String("protocol", "radius"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
	}
	fillRADIUSAttrs(&frame, pkt)
	events = append(events, frame)
	if err != nil {
		return nil
	}

	logger.Info("RADIUS request received",
		slog.String("handler", "radius"),
		slog.String("protocol", "radius"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
		slog.String("username", frame.Username),
	)

	resp := radius.Reply(pkt)
	if resp == nil || len(resp) > len(data) {
		return nil
	}
	status := "reject"
	switch resp[0] {
	case radius.CodeAccessAccept:
		status = "accept"
	case radius.CodeAccountingResponse:
		status = "ok"
	}
	events = append(events, parsedRADIUS{
		Direction:  "write",
		Command:    radius.CodeName(resp[0]),
		Identifier: int(resp[1]),
		Status:     status,
		Payload:    resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send RADIUS reply", slog.String("protocol", "radius"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}

func fillRADIUSAttrs(frame *parsedRADIUS, pkt radius.Packet) {
	for _, a := range pkt.Attrs {
		switch a.Type {
		case radius.AttrUserName:
			if frame.Username == "" {
				frame.Username = string(a.Value)
			}
		case radius.AttrUserPassword:
			if frame.PasswordHidden != "" {
				continue
			}
			frame.PasswordHidden = hex.EncodeToString(a.Value)
			if pw, ok := radius.DecryptPassword(pkt.Authenticator, a.Value); ok {
				frame.Password = pw
			}
		case radius.AttrCHAPPassword:
			if frame.CHAPPassword == "" {
				frame.CHAPPassword = hex.EncodeToString(a.Value)
			}
		case radius.AttrNASIPAddress:
			if len(a.Value) == 4 && frame.NASIP == "" {
				frame.NASIP = net.IP(a.Value).String()
			}
		case radius.AttrNASIdentifier:
			if frame.NASIdentifier == "" {
				frame.NASIdentifier = string(a.Value)
			}
		case radius.AttrCallingStationID:
			if frame.CallingStationID == "" {
				frame.CallingStationID = string(a.Value)
			}
		case radius.AttrCalledStationID:
			if frame.CalledStationID == "" {
				frame.CalledStationID = string(a.Value)
			}
		case radius.AttrMessageAuthenticator:
			frame.MessageAuthenticator = true
		}
	}
}
