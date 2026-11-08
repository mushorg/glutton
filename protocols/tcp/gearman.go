package tcp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/gearman"
)

const (
	maxGearmanMessages = 64
	// maxGearmanLine bounds an admin text line (and the bufio buffer).
	maxGearmanLine = 4096
)

// gearmanJobHost is the host part of fake job handles (H:<host>:<n>).
var gearmanJobHost = "ip-10-0-1-17"

type parsedGearman struct {
	Direction  string `json:"direction,omitempty"`
	Mode       string `json:"mode,omitempty"` // "binary" or "text" (admin protocol)
	Command    string `json:"command,omitempty"`
	PacketType uint32 `json:"packet_type,omitempty"`
	Function   string `json:"function,omitempty"`
	Unique     string `json:"unique,omitempty"`
	Handle     string `json:"handle,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type gearmanServer struct {
	events []parsedGearman
	conn   net.Conn
	reader *bufio.Reader
	state  *gearman.Server
}

func gearmanFrame(direction string, p gearman.Packet) parsedGearman {
	return parsedGearman{
		Direction:  direction,
		Mode:       "binary",
		Command:    p.Name(),
		PacketType: p.Type,
		Function:   p.Function(),
		Unique:     p.Unique(),
		Handle:     p.Handle(),
		Payload:    p.Raw,
	}
}

func (s *gearmanServer) write(data []byte, frame parsedGearman) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

var errGearmanLineTooLong = errors.New("gearman: admin line too long")

// readLine reads one admin text line. The returned slice is a copy; when the
// line exceeds maxGearmanLine the prefix is returned with errGearmanLineTooLong.
func (s *gearmanServer) readLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	data := append([]byte(nil), line...)
	if errors.Is(err, bufio.ErrBufferFull) {
		return data, errGearmanLineTooLong
	}
	return data, err
}

// HandleGearman takes a net.Conn and emulates a Gearman job server (binary
// protocol plus the admin text protocol) on tcp/4730.
func HandleGearman(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &gearmanServer{
		events: []parsedGearman{},
		conn:   conn,
		reader: bufio.NewReaderSize(conn, maxGearmanLine),
		state:  gearman.NewServer(gearmanJobHost),
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("gearman", conn, md, helpers.FirstOrEmpty[parsedGearman](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "gearman"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Gearman connection", slog.String("protocol", "gearman"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxGearmanMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "gearman"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		first, err := server.reader.Peek(1)
		if err != nil {
			endReason = connection.EndReasonFromRead(err)
			break
		}

		var (
			reply      []byte
			frame      parsedGearman
			closeAfter bool
		)
		if first[0] == 0 {
			p, err := gearman.ReadPacket(server.reader)
			if err != nil {
				if len(p.Raw) > 0 {
					server.events = append(server.events, parsedGearman{
						Direction: "read", Mode: "binary", Command: p.Name(), PacketType: p.Type,
						Payload: p.Raw, Truncated: true,
					})
				}
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					logger.Debug("Failed to read Gearman packet", slog.String("protocol", "gearman"), producer.ErrAttr(err))
				}
				endReason = connection.EndReasonFromRead(err)
				if errors.Is(err, gearman.ErrBadMagic) || errors.Is(err, gearman.ErrTooLarge) {
					endReason = connection.EndHandlerClose
				}
				break
			}
			frame = gearmanFrame("read", p)
			server.events = append(server.events, frame)
			reply = server.state.Reply(p)
			if reply != nil {
				if rp, err := gearman.ReadPacket(bytes.NewReader(reply)); err == nil {
					frame = gearmanFrame("write", rp)
				}
			}
		} else {
			line, err := server.readLine()
			if len(line) > 0 {
				server.events = append(server.events, parsedGearman{
					Direction: "read", Mode: "text", Command: gearman.AdminCommand(string(line)),
					Payload: line, Truncated: errors.Is(err, errGearmanLineTooLong),
				})
			}
			if err != nil {
				endReason = connection.EndReasonFromRead(err)
				if errors.Is(err, errGearmanLineTooLong) {
					endReason = connection.EndHandlerClose
				}
				break
			}
			cmd := gearman.AdminCommand(string(line))
			reply, closeAfter = server.state.AdminReply(string(line), host)
			frame = parsedGearman{Mode: "text", Command: cmd}
		}

		last := server.events[len(server.events)-1]
		logger.Info(
			"Gearman request",
			slog.String("handler", "gearman"),
			slog.String("protocol", "gearman"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("mode", last.Mode),
			slog.String("command", last.Command),
		)

		if len(reply) > 0 {
			if err := server.write(reply, frame); err != nil {
				logger.Error("Failed to write to connection", slog.String("protocol", "gearman"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if closeAfter {
			return nil
		}
	}
	if i >= maxGearmanMessages {
		endReason = connection.EndMaxFrames
	}
	return nil
}
