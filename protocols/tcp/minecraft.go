package tcp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/minecraft"
)

const maxMinecraftPackets = 16

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
		state     int32 // 0 handshake, then minecraft.StateStatus / StateLogin
		protocol  int32 = -1
		handshook bool
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
			protocol = hs.ProtocolVersion
			frame.Command = "handshake"
			frame.Path = hs.Address
			frame.ProtocolVersion = &hs.ProtocolVersion
			frame.Port = hs.Port
			frame.NextState = hs.NextState
			server.events = append(server.events, frame)
			if state != minecraft.StateStatus && state != minecraft.StateLogin {
				return nil
			}

		case state == minecraft.StateStatus && pkt.ID == minecraft.IDStatusReq:
			frame.Command = "status_request"
			server.events = append(server.events, frame)
			if err := server.write(minecraft.BuildStatusResponse(protocol), "status_response"); err != nil {
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
			frame.Command = "login_start"
			if name, err := minecraft.ParseLoginStart(pkt.Body); err == nil {
				frame.Username = name
			}
			server.events = append(server.events, frame)
			return server.write(minecraft.BuildLoginDisconnect(), "disconnect")

		default:
			frame.Command = "unknown"
			server.events = append(server.events, frame)
			return nil
		}
	}
	return nil
}
