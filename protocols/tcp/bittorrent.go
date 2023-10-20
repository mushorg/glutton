package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"go.uber.org/zap"
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
	Message   bittorrentMsg `json:"message,omitempty"`
	Payload   []byte        `json:"payload,omitempty"`
}

type bittorrentServer struct {
	events []parsedBittorrent
}

// HandleBittorrent handles a Bittorrent connection
func HandleBittorrent(ctx context.Context, conn net.Conn, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := bittorrentServer{
		events: []parsedBittorrent{},
	}
	defer func() {
		md, err := h.MetadataByConnection(conn)
		if err != nil {
			logger.Error("failed to fetch meta data", zap.Error(err), zap.String("handler", "bittorrent"))
		}
		if err = h.ProduceTCP("bittorrent", conn, md, helpers.FirstOrEmpty[parsedBittorrent](server.events).Payload, server.events); err != nil {
			logger.Error("failed to produce message", zap.Error(err), zap.String("handler", "bittorrent"))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close connection", zap.Error(err), zap.String("handler", "bittorrent"))
			return
		}
	}()

	logger.Info("new bittorrent connection")

	buffer := make([]byte, 1024)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Error("failed to read data", zap.Error(err), zap.String("handler", "bittorrent"))
			break
		}

		if n <= 0 {
			break
		}

		msg := bittorrentMsg{}
		if err := binary.Read(bytes.NewReader(buffer[:n]), binary.BigEndian, &msg); err != nil {
			logger.Error("failed to read message", zap.Error(err), zap.String("handler", "bittorrent"))
			break
		}

		server.events = append(server.events, parsedBittorrent{
			Direction: "read",
			Message:   msg,
			Payload:   buffer[:n],
		})

		logger.Info(
			"bittorrent received",
			zap.String("handler", "bittorrent"),
			zap.Uint8s("peer_id", msg.PeerID[:]),
			zap.Uint8s("inf_hash", msg.InfoHash[:]),
		)

		server.events = append(server.events, parsedBittorrent{
			Direction: "write",
			Message:   msg,
			Payload:   buffer[:n],
		})
		if err = binary.Write(conn, binary.BigEndian, msg); err != nil {
			logger.Error("failed to write message", zap.Error(err), zap.String("handler", "bittorrent"))
			break
		}
	}
	return nil
}
