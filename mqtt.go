package glutton

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"go.uber.org/zap"
)

type mqttMsg struct {
	HeaderFlag uint8
	Length     uint8
}

type mqttRes struct {
	HeaderFlag uint8
	Length     uint8
	Flags      uint8
	RetCode    uint8
}

// HandleMQTT handles a MQTT connection
func (g *Glutton) HandleMQTT(ctx context.Context, conn net.Conn) error {
	var err error
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[mqtt    ] error: %v", err))
		}
	}()
	buffer := make([]byte, 1024)
	for {
		g.updateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err == nil || n > 0 {
			msg := mqttMsg{}
			r := bytes.NewReader(buffer)
			if err := binary.Read(r, binary.LittleEndian, &msg); err != nil {
				break
			}
			g.logger.Info(fmt.Sprintf("new mqqt packet with header flag: %d", msg.HeaderFlag), zap.String("handler", "mqtt"))
			var res mqttRes
			switch msg.HeaderFlag {
			case 0x10:
				res = mqttRes{
					HeaderFlag: 0x20,
					Length:     2,
				}
			case 0x82:
				res = mqttRes{
					HeaderFlag: 0x90,
					Length:     3,
				}
			case 0xc0:
				res = mqttRes{
					HeaderFlag: 0xd0,
					Length:     0,
				}
			}
			var buf bytes.Buffer
			binary.Write(&buf, binary.LittleEndian, res)
			conn.Write(buf.Bytes())
		} else {
			break
		}
	}
	return nil
}
