package tcp

import (
	"context"
	"crypto/rand"
	"embed"
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

//go:embed responses/*
var embeddedFiles embed.FS

var responseFileMap = map[uint16]string{
	21:    "responses/21_tcp",
	25:    "responses/25_tcp",
	80:    "responses/80_tcp",
	110:   "responses/110_tcp",
	135:   "responses/135_tcp",
	139:   "responses/139_tcp",
	445:   "responses/445_tcp",
	1433:  "responses/1433_tcp",
	3306:  "responses/3306_tcp",
	4444:  "responses/4444_tcp",
	4899:  "responses/4899_tcp",
	5060:  "responses/5060_tcp",
	5900:  "responses/5900_tcp",
	8009:  "responses/8009_tcp",
	21000: "responses/21000_tcp",
}

func (s *tcpServer) getResponse(port uint16) ([]byte, error) {
	filePath, exists := responseFileMap[port]
	if !exists {
		return nil, fmt.Errorf("file not found for port: %v", port)
	}

	return embeddedFiles.ReadFile(filePath)
}

func (s *tcpServer) sendPortSpecificResponse(conn net.Conn, port uint16, logger interfaces.Logger) error {
	response, err := s.getResponse(port)
	if err != nil {
		// If no specific response file exists, fall back to random data
		logger.Debug("No specific response file found, sending random data",
			slog.String("handler", "tcp"),
			slog.Uint64("port", uint64(port)))
		return s.sendRandom(conn)
	}

	s.events = append(s.events, parsedTCP{
		Direction:   "write",
		PayloadHash: helpers.HashData(response),
		Payload:     response,
	})

	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
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

	// Send port-specific or random response
	if err := server.sendPortSpecificResponse(conn, md.TargetPort, logger); err != nil {
		logger.Error("write error", slog.String("handler", "tcp"), producer.ErrAttr(err))
	}

	return nil
}
