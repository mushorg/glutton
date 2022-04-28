package protocols

import (
	"context"
	"net"
	"strconv"
	"strings"
)

func HandleMemcache(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	var dataMap = map[string]string{}
	for {
		buffer := make([]byte, 1024)
		h.UpdateConnectionTimeout(ctx, conn)
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		if n == 0 {
			break
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
