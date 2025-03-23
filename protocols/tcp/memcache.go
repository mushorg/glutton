package tcp

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

func HandleMemcache(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var dataMap = map[string]string{}
	buffer := make([]byte, 1024)
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}

		if err = h.ProduceTCP("memcache", conn, md, buffer, nil); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "memcache"))
		}

		parts := strings.Split(string(buffer[:]), " ")
		switch parts[0] {
		case "set":
			if len(parts) < 6 {
				break
			}
			dataMap[parts[1]] = parts[5]
		case "get":
			if len(parts) < 2 {
				break
			}
			val := dataMap[parts[1]]
			_, err := conn.Write([]byte(parts[1] + " 0 " + strconv.Itoa(len(val)) + " " + val + "\r\n"))
			if err != nil {
				return err
			}
		}
	}
	return nil
}
