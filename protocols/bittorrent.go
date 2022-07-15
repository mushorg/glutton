package protocols

import (
	"bytes"
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

	logger.Info("new bittorrent connection")

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}

	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil || n > 0 {
			msg := bittorrentMsg{}
			if err := binary.Read(bytes.NewReader(buffer), binary.BigEndian, &msg); err != nil {
				logger.Error("failed to read message", zap.Error(err), zap.String("handler", "bittorrent"))
				break
			}
			if err = h.Produce(conn, md, buffer); err != nil {
				logger.Error("failed to produce message", zap.Error(err), zap.String("handler", "bittorrent"))
			}

			logger.Info(
				"bittorrent received",
				zap.String("handler", "bittorrent"),
				zap.Uint8s("peer_id", msg.PeerID[:]),
				zap.Uint8s("inf_hash", msg.InfoHash[:]),
			)

			if err = binary.Write(conn, binary.BigEndian, msg); err != nil {
				logger.Error("failed to write message", zap.Error(err), zap.String("handler", "bittorrent"))
				break
			}
		} else {
			logger.Info("failed to read from connection", zap.String("handler", "bittorrent"))
			if err != nil {
				logger.Error("failed to read data", zap.Error(err), zap.String("handler", "bittorrent"))
				break
			}
		}
	}
	return nil
}
