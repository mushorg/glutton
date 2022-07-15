package protocols

import (
	"context"
	"encoding/binary"
	"net"

	"go.uber.org/zap"
)

type bittorrentMsg struct {
	Length             uint8
	ProtocolIdentifier [19]uint8
	Reserved           [8]uint8
	InfoHash           [20]uint8
	PeerID             [20]uint8
}

// HandleBittorrent handles a Bittorrent connection
func HandleBittorrent(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	var err error
	defer func() {
		if err = conn.Close(); err != nil {
			logger.Error("failed to close connection", zap.Error(err), zap.String("handler", "bittorrent"))
			return
		}
	}()
	for {
		msg := bittorrentMsg{}
		if err := binary.Read(conn, binary.BigEndian, &msg); err != nil {
			logger.Error("failed to read message", zap.Error(err), zap.String("handler", "bittorrent"))
			break
		}
		md, err := h.MetadataByConnection(conn)
		if err != nil {
			return err
		}
		if err = h.Produce(conn, md, []byte{}); err != nil {
			logger.Error("failed to produce message", zap.Error(err), zap.String("handler", "bittorrent"))
		}

		logger.Info(
			"telnet send",
			zap.String("handler", "bittorrent"),
			zap.Uint8s("peer_id", msg.PeerID[:]),
			zap.Uint8s("inf_hash", msg.InfoHash[:]),
		)

		if err = binary.Write(conn, binary.BigEndian, msg); err != nil {
			logger.Error("failed to write message", zap.Error(err), zap.String("handler", "bittorrent"))
			break
		}
	}
	return nil
}
