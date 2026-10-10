package tcp

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/minecraft"
)

const maxMinecraftPackets = 16

// minecraftLingerWait bounds the read of a Login Start already in flight when
// a login Handshake is rejected, so its username is still captured. Tests
// shorten it.
var minecraftLingerWait = 500 * time.Millisecond

type parsedMinecraft struct {
	Direction       string `json:"direction,omitempty"`
	Command         string `json:"command,omitempty"`
	Path            string `json:"path,omitempty"` // server address from the handshake
	Status          string `json:"status,omitempty"`
	ProtocolVersion *int32 `json:"protocol_version,omitempty"`
	Port            uint16 `json:"port,omitempty"`
	NextState       int32  `json:"next_state,omitempty"`
	Username        string `json:"username,omitempty"`
	Payload         []byte `json:"payload,omitempty"`
	Truncated       bool   `json:"truncated,omitempty"`
}

type minecraftServer struct {
	events []parsedMinecraft
	conn   net.Conn
}

func (s *minecraftServer) write(data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedMinecraft{Direction: "write", Status: status, Payload: data})
	return nil
}

// disconnect sends a login Disconnect; the frame status is the reason key
// without its "multiplayer.disconnect." prefix (e.g. "not_whitelisted").
func (s *minecraftServer) disconnect(reason string) error {
	return s.write(minecraft.BuildLoginDisconnect(reason), strings.TrimPrefix(reason, "multiplayer.disconnect."))
}

// readLingeringLogin records a Login Start the client sent before it saw the
// Disconnect. Nothing is answered.
func (s *minecraftServer) readLingeringLogin() {
	if err := s.conn.SetReadDeadline(time.Now().Add(minecraftLingerWait)); err != nil {
		return
	}
	pkt, err := minecraft.ReadPacket(s.conn)
	if err != nil {
		if len(pkt.Raw) > 0 {
			s.events = append(s.events, parsedMinecraft{Direction: "read", Command: "malformed", Payload: pkt.Raw, Truncated: true})
		}
		return
	}
	s.events = append(s.events, loginStartFrame(pkt))
}

func loginStartFrame(pkt minecraft.Packet) parsedMinecraft {
	frame := parsedMinecraft{Direction: "read", Command: "unknown", Payload: pkt.Raw}
	if pkt.ID == minecraft.IDLoginStart {
		frame.Command = "login_start"
		if name, err := minecraft.ParseLoginStart(pkt.Body); err == nil {
			frame.Username = name
		}
	}
	return frame
}

// HandleMinecraft answers Minecraft Java server-list pings and records login attempts.
func HandleMinecraft(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &minecraftServer{events: []parsedMinecraft{}, conn: conn}
	defer func() {
		if err := h.ProduceTCP("minecraft", conn, md, helpers.FirstOrEmpty[parsedMinecraft](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Minecraft connection", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
		}
	}()

	var (
		state      int32 // 0 handshake, then minecraft.StateStatus / StateLogin
		handshook  bool
		statusSent bool
	)

	for i := 0; i < maxMinecraftPackets; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return nil
		}
		pkt, err := minecraft.ReadPacket(conn)
		if err != nil {
			if len(pkt.Raw) > 0 {
				// Partial or rejected frame: keep what the attacker sent.
				server.events = append(server.events, parsedMinecraft{
					Direction: "read",
					Command:   "malformed",
					Payload:   pkt.Raw,
					Truncated: true,
				})
			}
			logger.Debug("Failed to read data", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return nil
		}
		frame := parsedMinecraft{Direction: "read", Payload: pkt.Raw}

		switch {
		case !handshook:
			hs, err := minecraft.ParseHandshake(pkt.Body)
			if pkt.ID != minecraft.IDHandshake || err != nil {
				frame.Command = "unknown"
				server.events = append(server.events, frame)
				return nil
			}
			handshook = true
			state = hs.NextState
			frame.Command = "handshake"
			frame.Path = hs.Address
			frame.ProtocolVersion = &hs.ProtocolVersion
			frame.Port = hs.Port
			frame.NextState = hs.NextState
			server.events = append(server.events, frame)
			// Vanilla rejects transfers and version mismatches right after
			// the Handshake, before Login Start.
			var reason string
			switch state {
			case minecraft.StateStatus:
			case minecraft.StateLogin:
				reason = minecraft.VersionReason(hs.ProtocolVersion)
			case minecraft.StateTransfer:
				reason = minecraft.ReasonTransfersDisabled
			default:
				return nil
			}
			if reason != "" {
				if err := server.disconnect(reason); err != nil {
					return err
				}
				server.readLingeringLogin()
				return nil
			}

		case state == minecraft.StateStatus && pkt.ID == minecraft.IDStatusReq:
			frame.Command = "status_request"
			server.events = append(server.events, frame)
			if statusSent {
				// Vanilla closes on a second Status Request.
				return nil
			}
			statusSent = true
			if err := server.write(minecraft.BuildStatusResponse(), "status_response"); err != nil {
				return err
			}

		case state == minecraft.StateStatus && pkt.ID == minecraft.IDPing:
			frame.Command = "ping"
			server.events = append(server.events, frame)
			ping, err := minecraft.ParsePing(pkt.Body)
			if err != nil {
				return nil
			}
			return server.write(minecraft.BuildPong(ping), "pong")

		case state == minecraft.StateLogin && pkt.ID == minecraft.IDLoginStart:
			server.events = append(server.events, loginStartFrame(pkt))
			return server.disconnect(minecraft.ReasonNotWhitelisted)

		default:
			frame.Command = "unknown"
			server.events = append(server.events, frame)
			return nil
		}
	}
	return nil
}
