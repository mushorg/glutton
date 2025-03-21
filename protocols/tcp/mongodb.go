package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type mongoMsgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// OpCode values for the MongoDB wire protocol
const (
	OpReply       = 1
	OpUpdate      = 2001
	OpInsert      = 2002
	OpQuery       = 2004
	OpGetMore     = 2005
	OpDelete      = 2006
	OpKillCursors = 2007
	OpCompressed  = 2012
	OpMsg         = 2013
)

var opCodeNames = map[int32]string{
	OpReply:       "OP_REPLY",
	OpUpdate:      "OP_UPDATE",
	OpInsert:      "OP_INSERT",
	OpQuery:       "OP_QUERY",
	OpGetMore:     "OP_GET_MORE",
	OpDelete:      "OP_DELETE",
	OpKillCursors: "OP_KILL_CURSORS",
	OpCompressed:  "OP_COMPRESSED",
	OpMsg:         "OP_MSG",
}

type parsedMongoDB struct {
	Direction string         `json:"direction,omitempty"`
	Header    mongoMsgHeader `json:"header,omitempty"`
	Payload   []byte         `json:"payload,omitempty"`
	OpCodeStr string         `json:"opcode_str,omitempty"`
}

type mongoDBServer struct {
	events []parsedMongoDB
	conn   net.Conn
}

func (s *mongoDBServer) read() ([]byte, error) {
	// read message header
	headerBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, headerBytes); err != nil {
		return nil, err
	}

	var header mongoMsgHeader
	if err := binary.Read(bytes.NewReader(headerBytes), binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	// check to prevent excessive mem alloc
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

// writes a Mongo message to the connection
func (s *mongoDBServer) write(header mongoMsgHeader, data []byte) error {
	_, err := s.conn.Write(data)
	if err != nil {
		return err
	}

	s.events = append(s.events, parsedMongoDB{
		Direction: "write",
		Header:    header,
		Payload:   data,
		OpCodeStr: opCodeNames[header.OpCode],
	})

	return nil
}

// creates a basic "ok" response for Mongo queries
func createOkResponse(requestHeader mongoMsgHeader) (mongoMsgHeader, []byte, error) {
	buffer := new(bytes.Buffer)

	responseHeader := mongoMsgHeader{
		MessageLength: 0, // will fill in later
		RequestID:     requestHeader.RequestID + 1,
		ResponseTo:    requestHeader.RequestID,
		OpCode:        OpMsg, // using OP_MSG for responses
	}

	// write placeholder for header
	if err := binary.Write(buffer, binary.LittleEndian, responseHeader); err != nil {
		return responseHeader, nil, err
	}

	// OP_MSG flags - no special flags set
	flagBits := uint32(0)
	if err := binary.Write(buffer, binary.LittleEndian, flagBits); err != nil {
		return responseHeader, nil, err
	}

	// section kind 0 (Body)
	sectionKind := byte(0)
	if err := binary.Write(buffer, binary.LittleEndian, sectionKind); err != nil {
		return responseHeader, nil, err
	}

	// simple document with ok:1
	document := []byte{
		0x11, 0x00, 0x00, 0x00, // doc size - 17 bytes
		0x01, 'o', 'k', 0x00, // "ok" (type double)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, // double value 1.0
		0x00, // terminator
	}

	if _, err := buffer.Write(document); err != nil {
		return responseHeader, nil, err
	}

	response := buffer.Bytes()

	messageLength := int32(len(response))
	binary.LittleEndian.PutUint32(response[0:4], uint32(messageLength))

	responseHeader.MessageLength = messageLength

	return responseHeader, response, nil
}

func HandleMongoDB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mongoDBServer{
		events: []parsedMongoDB{},
		conn:   conn,
	}

	defer func() {
		if err := h.ProduceTCP("mongodb", conn, md, helpers.FirstOrEmpty[parsedMongoDB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce MongoDB event", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MongoDB connection", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
		}
	}()

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to split remote address: %w", err)
	}

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to update connection timeout", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			return nil
		}

		message, err := server.read()
		if err != nil {
			if err != io.EOF {
				logger.Debug("Failed to read MongoDB message", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			}
			break
		}

		var header mongoMsgHeader
		if err := binary.Read(bytes.NewReader(message[:16]), binary.LittleEndian, &header); err != nil {
			logger.Error("Failed to parse MongoDB header", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			break
		}

		server.events = append(server.events, parsedMongoDB{
			Direction: "read",
			Header:    header,
			Payload:   message,
			OpCodeStr: opCodeNames[header.OpCode],
		})

		logger.Info(
			"MongoDB message received",
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("opcode", opCodeNames[header.OpCode]),
			slog.Int("message_length", int(header.MessageLength)),
			slog.Int("request_id", int(header.RequestID)),
			slog.String("handler", "mongodb"),
		)

		logger.Debug(fmt.Sprintf("MongoDB payload:\n%s", hex.Dump(message)))

		responseHeader, response, err := createOkResponse(header)
		if err != nil {
			logger.Error("Failed to create MongoDB response", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			break
		}

		if err := server.write(responseHeader, response); err != nil {
			logger.Error("Failed to write MongoDB response", producer.ErrAttr(err), slog.String("protocol", "mongodb"))
			break
		}
	}

	return nil
}
