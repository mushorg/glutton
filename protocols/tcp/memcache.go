package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

// Cap session length so a noisy client cannot grow events without bound.
const maxMemcacheCommands = 100

// Cap set body size; larger values are rejected with CLIENT_ERROR.
const maxMemcacheBody = 1024

type parsedMemcache struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // verb for client command frames (stats, get, set, ...)
	Payload   []byte `json:"payload,omitempty"`   // raw bytes as seen on the wire
}

type memcacheServer struct {
	events  []parsedMemcache
	conn    net.Conn
	bufin   *bufio.Reader
	dataMap map[string]string
}

func newMemcacheServer(conn net.Conn) *memcacheServer {
	return &memcacheServer{
		events:  []parsedMemcache{},
		conn:    conn,
		bufin:   bufio.NewReader(conn),
		dataMap: map[string]string{},
	}
}

func (s *memcacheServer) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedMemcache{
		Direction: "write",
		Payload:   data,
	})
	return nil
}

func (s *memcacheServer) readLine() (string, error) {
	return s.bufin.ReadString('\n')
}

func (s *memcacheServer) recordRead(command string, payload []byte) {
	s.events = append(s.events, parsedMemcache{
		Direction: "read",
		Command:   command,
		Payload:   payload,
	})
}

func memcacheVerb(line string) string {
	line = strings.Trim(line, "\r\n")
	if line == "" {
		return ""
	}
	verb := line
	if idx := strings.IndexByte(line, ' '); idx >= 0 {
		verb = line[:idx]
	}
	return strings.ToLower(verb)
}

func memcacheStatsResponse() []byte {
	var b strings.Builder
	for _, line := range []string{
		"STAT pid 1",
		"STAT uptime 12345",
		"STAT time 1700000000",
		"STAT version 1.6.22",
		"STAT curr_connections 1",
		"STAT total_connections 1",
		"STAT cmd_get 0",
		"STAT cmd_set 0",
		"STAT bytes 0",
		"END",
	} {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func memcacheGetResponse(keys []string, dataMap map[string]string) []byte {
	var b strings.Builder
	for _, key := range keys {
		val, ok := dataMap[key]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "VALUE %s 0 %d\r\n%s\r\n", key, len(val), val)
	}
	b.WriteString("END\r\n")
	return []byte(b.String())
}

// HandleMemcache takes a net.Conn and does basic Memcached text-protocol communication.
func HandleMemcache(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleMemcache(ctx, newMemcacheServer(conn), md, logger, h)
}

func handleMemcache(ctx context.Context, server *memcacheServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	defer func() {
		if err := h.ProduceTCP("memcache", conn, md, helpers.FirstOrEmpty[parsedMemcache](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "memcache"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close memcache connection", slog.String("protocol", "memcache"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < maxMemcacheCommands; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "memcache"), producer.ErrAttr(err))
			return nil
		}

		line, err := server.readLine()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "memcache"), producer.ErrAttr(err))
			break
		}

		command := memcacheVerb(line)
		payload := []byte(line)
		parts := strings.Fields(strings.Trim(line, "\r\n"))

		switch command {
		case "stats":
			server.recordRead(command, payload)
			if err := server.write(memcacheStatsResponse()); err != nil {
				return err
			}
		case "get", "gets":
			server.recordRead(command, payload)
			keys := []string{}
			if len(parts) > 1 {
				keys = parts[1:]
			}
			if err := server.write(memcacheGetResponse(keys, server.dataMap)); err != nil {
				return err
			}
		case "set", "add", "replace":
			if len(parts) < 5 {
				server.recordRead(command, payload)
				if err := server.write([]byte("CLIENT_ERROR bad command line format\r\n")); err != nil {
					return err
				}
				continue
			}
			nbytes, err := strconv.Atoi(parts[4])
			if err != nil || nbytes < 0 || nbytes > maxMemcacheBody {
				server.recordRead(command, payload)
				if err := server.write([]byte("CLIENT_ERROR bad data chunk\r\n")); err != nil {
					return err
				}
				continue
			}
			body := make([]byte, nbytes+2) // data + trailing \r\n
			if _, err := io.ReadFull(server.bufin, body); err != nil {
				server.recordRead(command, payload)
				logger.Debug("Failed to read set body", slog.String("protocol", "memcache"), producer.ErrAttr(err))
				break
			}
			// Keep the CRLF terminator in the stored payload; strip it from the value map.
			value := body[:nbytes]
			payload = append(payload, body...)
			server.recordRead(command, payload)
			server.dataMap[parts[1]] = string(value)
			noreply := len(parts) >= 6 && parts[5] == "noreply"
			if !noreply {
				if err := server.write([]byte("STORED\r\n")); err != nil {
					return err
				}
			}
		case "quit":
			server.recordRead(command, payload)
			return nil
		case "version":
			server.recordRead(command, payload)
			if err := server.write([]byte("VERSION 1.6.22\r\n")); err != nil {
				return err
			}
		default:
			server.recordRead(command, payload)
			if err := server.write([]byte("ERROR\r\n")); err != nil {
				return err
			}
		}
	}
	return nil
}
