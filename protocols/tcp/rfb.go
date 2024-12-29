package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

func readRFB(conn net.Conn, logger interfaces.Logger) error {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	logger.Debug("RFB message", slog.String("msg", msg), slog.String("protocol", "rfb"))
	return nil
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
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close RFB connection", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		}
	}()

	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	if err := readRFB(conn, logger); err != nil {
		logger.Debug("Failed to read RFB", slog.String("protocol", "rfb"), producer.ErrAttr(err))
		return nil
	}
	var authNone uint32 = 1
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, authNone)
	if _, err := conn.Write(bs); err != nil {
		return err
	}

	serverName := "rfb-go"
	lenName := int32(len(serverName))

	buf := new(bytes.Buffer)
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
	if err := binary.Write(buf, binary.LittleEndian, f); err != nil {
		return err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return readRFB(conn, logger)
}
