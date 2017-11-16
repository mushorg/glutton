package glutton

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

func readRFB(conn net.Conn, g *Glutton) {
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		g.logger.Error(fmt.Sprintf("[rfb     ] error: %v", err))
	}
	g.logger.Info(fmt.Sprintf("[rfb     ] message %q", msg))
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
func (g *Glutton) HandleRFB(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[rfb     ] error: %v", err))
		}
	}()

	conn.Write([]byte("RFB 003.008\n"))
	readRFB(conn, g)
	var authNone uint32 = 1
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, authNone)
	conn.Write(bs)

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
	err = binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		g.logger.Warn(fmt.Sprintf("[rfb     ] binary.Write failed, error: %+v", err))
	}
	conn.Write(buf.Bytes())
	readRFB(conn, g)
	return err
}
