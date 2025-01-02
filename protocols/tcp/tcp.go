package tcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/spf13/viper"
)

type parsedTCP struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type tcpServer struct {
	events []parsedTCP
}

func (s *tcpServer) sendRandom(conn net.Conn) error {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(500))
	if err != nil {
		return err
	}
	randomBytes := make([]byte, 12+randomInt.Int64())
	if _, err := rand.Read(randomBytes); err != nil {
		return err
	}
	s.events = append(s.events, parsedTCP{
		Direction:   "write",
		PayloadHash: hex.EncodeToString(randomBytes),
		Payload:     randomBytes,
	})
	if _, err := conn.Write(randomBytes); err != nil {
		return err
	}
	return nil
}

// HandleTCP takes a net.Conn and peeks at the data send
func HandleTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := tcpServer{
		events: []parsedTCP{},
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("faild to split remote address: %w", err)
	}

	msgLength := 0
	data := []byte{}
	buffer := make([]byte, 1024)

	defer func() {
		if msgLength > 0 {
			payloadHash, err := helpers.StorePayload(data)
			if err != nil {
				logger.Error("Failed to store payload", slog.String("handler", "tcp"), producer.ErrAttr(err))
			}
			logger.Info(
				"Packet got handled by TCP handler",
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("handler", "tcp"),
				slog.String("payload_hash", payloadHash),
			)
			logger.Info(fmt.Sprintf("TCP payload:\n%s", hex.Dump(data[:msgLength%1024])))

			server.events = append(server.events, parsedTCP{
				Direction:   "read",
				PayloadHash: payloadHash,
				Payload:     data[:msgLength%1024],
			})
		}

		if err := h.ProduceTCP("tcp", conn, md, helpers.FirstOrEmpty[parsedTCP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "tcp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close TCP connection", slog.String("handler", "tcp"), producer.ErrAttr(err))
		}
	}()

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Error("read error", slog.String("handler", "tcp"), producer.ErrAttr(err))
			break
		}
		msgLength += n
		data = append(data, buffer[:n]...)
		if n < 1024 {
			break
		}
		if msgLength > viper.GetInt("max_tcp_payload") {
			logger.Debug("max message length reached", slog.String("handler", "tcp"))
			break
		}
	}

	// sending some random data
	if err := server.sendRandom(conn); err != nil {
		logger.Error("write error", slog.String("handler", "tcp"), producer.ErrAttr(err))
	}

	return nil
}
