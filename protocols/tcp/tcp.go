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
	"github.com/mushorg/glutton/protocols/tcp/banners"

	"github.com/spf13/viper"
)

type parsedTCP struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"` // matched payload signature on reads
	Status      string `json:"status,omitempty"`  // canned response name, or "random", on writes
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type tcpServer struct {
	events []parsedTCP
	conn   net.Conn
}

func randomReply() ([]byte, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(500))
	if err != nil {
		return nil, err
	}
	randomBytes := make([]byte, 12+randomInt.Int64())
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func (s *tcpServer) write(data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedTCP{
		Direction:   "write",
		Status:      status,
		PayloadHash: helpers.SHA256Hex(data),
		Payload:     data,
	})
	return nil
}

func (s *tcpServer) captureRead(data []byte, payloadHash, command string) {
	s.events = append(s.events, parsedTCP{
		Direction:   "read",
		Command:     command,
		PayloadHash: payloadHash,
		Payload:     data,
	})
}

// HasServerBanner reports whether the catch-all greets clients on port before
// they send anything, so dispatch must not wait for client bytes.
func HasServerBanner(port uint16) bool {
	resp, ok := banners.ForPort(port)
	return ok && resp.ServerFirst
}

// HandleTCP takes a net.Conn, captures what the client sends and answers with
// a canned service response (by payload signature, then destination port),
// falling back to random bytes. Server-first ports get their banner on connect.
func HandleTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := tcpServer{
		events: []parsedTCP{},
		conn:   conn,
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("faild to split remote address: %w", err)
	}

	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("tcp", conn, md, helpers.FirstOrEmpty(server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "tcp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close TCP connection", slog.String("handler", "tcp"), producer.ErrAttr(err))
		}
	}()

	portResp, hasPortResp := banners.ForPort(md.TargetPort)
	if hasPortResp && portResp.ServerFirst {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			endReason = connection.EndTimeout
			return err
		}
		if err := server.write(portResp.Data, portResp.Name); err != nil {
			logger.Debug("Failed to write banner", slog.String("protocol", "tcp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}

	msgLength := 0
	data := []byte{}
	buffer := make([]byte, maxBufferSize)

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			endReason = connection.EndTimeout
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("read error", slog.String("handler", "tcp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
		msgLength += n
		data = append(data, buffer[:n]...)
		if n < maxBufferSize {
			break
		}
		if msgLength > viper.GetInt("max_tcp_payload") {
			logger.Debug("max message length reached", slog.String("handler", "tcp"))
			endReason = connection.EndMaxFrames
			break
		}
	}

	if len(data) > 0 {
		payloadHash, err := helpers.Store(data, "payloads")
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
		dumpLen := len(data)
		if dumpLen > 1024 {
			dumpLen = 1024
		}
		logger.Info(fmt.Sprintf("TCP payload:\n%s", hex.Dump(data[:dumpLen])))
		sigResp, matched := banners.ForPayload(data)
		command := ""
		if matched {
			command = sigResp.Name
		}
		server.captureRead(data, payloadHash, command)

		reply, status := sigResp.Data, sigResp.Name
		switch {
		case matched:
		case hasPortResp && !portResp.ServerFirst:
			reply, status = portResp.Data, portResp.Name
		default:
			if reply, err = randomReply(); err != nil {
				logger.Error("Failed to generate random reply", slog.String("handler", "tcp"), producer.ErrAttr(err))
				return nil
			}
			status = "random"
		}
		if err := server.write(reply, status); err != nil {
			logger.Error("write error", slog.String("handler", "tcp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
		}
	}

	return nil
}
