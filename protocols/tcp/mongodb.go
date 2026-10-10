package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/mongodb"
)

const maxMongoMessages = 64

var opCodeNames = map[int32]string{
	mongodb.OpReply:       "OP_REPLY",
	mongodb.OpUpdate:      "OP_UPDATE",
	mongodb.OpInsert:      "OP_INSERT",
	mongodb.OpQuery:       "OP_QUERY",
	mongodb.OpGetMore:     "OP_GET_MORE",
	mongodb.OpDelete:      "OP_DELETE",
	mongodb.OpKillCursors: "OP_KILL_CURSORS",
	mongodb.OpCompressed:  "OP_COMPRESSED",
	mongodb.OpMsg:         "OP_MSG",
}

type parsedMongoDB struct {
	Direction string         `json:"direction,omitempty"`
	Header    mongodb.Header `json:"header,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
	OpCodeStr string         `json:"opcode_str,omitempty"`
	Command   string         `json:"command,omitempty"`
	Status    string         `json:"status,omitempty"`
}

type mongoDBServer struct {
	events []parsedMongoDB
	conn   net.Conn
}

func (s *mongoDBServer) read() ([]byte, error) {
	headerBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, headerBytes); err != nil {
		return nil, err
	}

	var header mongodb.Header
	if err := binary.Read(bytes.NewReader(headerBytes), binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if header.MessageLength <= 0 || header.MessageLength > 48*1024*1024 {
		return nil, fmt.Errorf("invalid MongoDB message length: %d", header.MessageLength)
	}

	fullMessage := make([]byte, header.MessageLength)
	copy(fullMessage, headerBytes)

	if _, err := io.ReadFull(s.conn, fullMessage[16:]); err != nil {
		return nil, err
	}

	return fullMessage, nil
}

func (s *mongoDBServer) write(header mongodb.Header, data []byte, command string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}

	s.events = append(s.events, parsedMongoDB{
		Direction: "write",
		Header:    header,
		Payload:   data,
		OpCodeStr: opCodeNames[header.OpCode],
		Command:   command,
		Status:    "ok",
	})

	return nil
}

func HandleMongoDB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mongoDBServer{
		events: []parsedMongoDB{},
		conn:   conn,
	}

	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("mongodb", conn, md, helpers.FirstOrEmpty[parsedMongoDB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce MongoDB event", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MongoDB connection", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxMongoMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to update connection timeout", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			endReason = connection.EndTimeout
			return nil
		}

		message, err := server.read()
		if err != nil {
			if err != io.EOF {
				logger.Debug("Failed to read MongoDB message", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			}
			endReason = connection.EndReasonFromRead(err)
			break
		}

		var header mongodb.Header
		if err := binary.Read(bytes.NewReader(message[:16]), binary.LittleEndian, &header); err != nil {
			logger.Error("Failed to parse MongoDB header", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			break
		}

		command := mongodb.CommandName(header.OpCode, message)
		server.events = append(server.events, parsedMongoDB{
			Direction: "read",
			Header:    header,
			Payload:   message,
			OpCodeStr: opCodeNames[header.OpCode],
			Command:   command,
		})

		logger.Info(
			"MongoDB message received",
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("opcode", opCodeNames[header.OpCode]),
			slog.String("command", command),
			slog.Int("message_length", int(header.MessageLength)),
			slog.Int("request_id", int(header.RequestID)),
			slog.String("handler", "mongodb"),
		)

		responseHeader, response, err := mongodb.BuildResponse(header, command)
		if err != nil {
			logger.Error("Failed to create MongoDB response", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			break
		}

		if err := server.write(responseHeader, response, command); err != nil {
			logger.Error("Failed to write MongoDB response", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			endReason = connection.EndWriteError
			break
		}
	}
	if i >= maxMongoMessages {
		endReason = connection.EndMaxFrames
	}

	return nil
}
