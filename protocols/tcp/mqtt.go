package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
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
func HandleMQTT(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	defer func() {
		err = conn.Close()
		if err != nil {
			logger.Error(fmt.Sprintf("[mqtt    ] error: %v", err))
		}
	}()
	buffer := make([]byte, 1024)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err == nil || n > 0 {
			msg := mqttMsg{}
			r := bytes.NewReader(buffer)
			if err := binary.Read(r, binary.LittleEndian, &msg); err != nil {
				break
			}

			if err = h.ProduceTCP("mqtt", conn, md, buffer, msg); err != nil {
				logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "mqtt"))
			}

			logger.Info(fmt.Sprintf("new mqqt packet with header flag: %d", msg.HeaderFlag), slog.String("handler", "mqtt"))
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
			if err = binary.Write(&buf, binary.LittleEndian, res); err != nil {
				logger.Error("Failed to write buffer", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
				break
			}
			if _, err = conn.Write(buf.Bytes()); err != nil {
				logger.Error("Failed to write message", producer.ErrAttr(err), slog.String("handler", "bittorrent"))
				break
			}
		} else {
			break
		}
	}
	return nil
}
