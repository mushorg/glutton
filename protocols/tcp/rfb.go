package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type parsedRFB struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
}

type rfbServer struct {
	events []parsedRFB
	conn   net.Conn
}

func (s *rfbServer) write(command string, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedRFB{Direction: "write", Command: command, Payload: data})
	return nil
}

func (s *rfbServer) read(command string) error {
	msg, err := bufio.NewReader(s.conn).ReadString('\n')
	if len(msg) > 0 {
		s.events = append(s.events, parsedRFB{Direction: "read", Command: command, Payload: []byte(msg)})
	}
	return err
}

// PixelFormat represents a RFB communication unit
type PixelFormat struct {
	Width, Heigth                   uint16
	BPP, Depth                      uint8
	BigEndian, TrueColour           uint8 // flags; 0 or non-zero
	RedMax, GreenMax, BlueMax       uint16
	RedShift, GreenShift, BlueShift uint8
	Padding                         [3]uint8
	ServerNameLength                int32
}

// HandleRFB takes a net.Conn and does basic RFB/VNC communication
func HandleRFB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rfbServer{conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rfb", conn, md, helpers.FirstOrEmpty[parsedRFB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RFB connection", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	if err := server.write("ProtocolVersion", []byte("RFB 003.008\n")); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	if err := server.read("ProtocolVersion"); err != nil {
		logger.Debug("Failed to read RFB", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	var authNone uint32 = 1
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, authNone)
	if err := server.write("Security", bs); err != nil {
		endReason = connection.EndWriteError
		return err
	}

	serverName := "rfb-go"
	lenName := int32(len(serverName))

	f := PixelFormat{
		Width:            1,
		Heigth:           1,
		BPP:              16,
		Depth:            16,
		BigEndian:        0,
		TrueColour:       1,
		RedMax:           0x1f,
		GreenMax:         0x1f,
		BlueMax:          0x1f,
		RedShift:         0xa,
		GreenShift:       0x5,
		BlueShift:        0,
		ServerNameLength: lenName,
	}
	if err := binary.Write(conn, binary.LittleEndian, f); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	// PixelFormat is written without going through write(); record it.
	server.events = append(server.events, parsedRFB{Direction: "write", Command: "ServerInit"})
	if err := server.read("ClientInit"); err != nil {
		logger.Debug("Failed to read RFB", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	return nil
}
