package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type bittorrentMsg struct {
	Length             uint8     `json:"length,omitempty"`
	ProtocolIdentifier [19]uint8 `json:"protocol_identifier,omitempty"`
	Reserved           [8]uint8  `json:"reserved,omitempty"`
	InfoHash           [20]uint8 `json:"info_hash,omitempty"`
	PeerID             [20]uint8 `json:"peer_id,omitempty"`
}

type parsedBittorrent struct {
	Direction string        `json:"direction,omitempty"`
	Command   string        `json:"command,omitempty"`
	Message   bittorrentMsg `json:"message,omitempty"`
	Payload   []byte        `json:"payload,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

type bittorrentServer struct {
	events []parsedBittorrent
}

// HandleBittorrent handles a Bittorrent connection
func HandleBittorrent(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := bittorrentServer{
		events: []parsedBittorrent{},
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("bittorrent", conn, md, helpers.FirstOrEmpty[parsedBittorrent](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close connection", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
			return
		}
	}()

	buffer := make([]byte, maxBufferSize)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
			endReason = connection.EndTimeout
			return nil
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Failed to read data", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
			endReason = connection.EndReasonFromRead(err)
			break
		}

		if n <= 0 {
			endReason = connection.EndClientClose
			break
		}

		payload := make([]byte, n)
		copy(payload, buffer[:n])
		truncated := n == maxBufferSize
		msg := bittorrentMsg{}
		if err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &msg); err != nil {
			logger.Error("Failed to read message", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
			server.events = append(server.events, parsedBittorrent{
				Direction: "read",
				Command:   "handshake",
				Payload:   payload,
				Truncated: truncated,
			})
			endReason = connection.EndReadError
			break
		}

		server.events = append(server.events, parsedBittorrent{
			Direction: "read",
			Command:   "handshake",
			Message:   msg,
			Payload:   payload,
			Truncated: truncated,
		})

		logger.Info(
			"bittorrent received",
			slog.String("handler", "bittorrent"),
			slog.Any("peer_id", msg.PeerID[:]),
			slog.Any("inf_hash", msg.InfoHash[:]),
		)

		server.events = append(server.events, parsedBittorrent{
			Direction: "write",
			Command:   "handshake",
			Message:   msg,
			Payload:   payload,
		})
		if err = binary.Write(conn, binary.BigEndian, msg); err != nil {
			logger.Error("Failed to write message", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
			endReason = connection.EndWriteError
			break
		}
	}
	return nil
}
