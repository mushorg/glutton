package tcp

import (
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
	"github.com/mushorg/glutton/protocols/tcp/dnp3"
	"github.com/spf13/viper"
)

const (
	// maxDNP3Frames caps the read frames kept per session. Address sweeps send
	// hundreds of header-only frames back to back.
	maxDNP3Frames = 512
	// defaultDNP3Address is the outstation link address when dnp3.address is unset.
	defaultDNP3Address = 10
)

// parsedDNP3 is one link-layer frame of the session. Dest and Src are always
// present because address 0 is a valid probe target; they are 0 on UNKNOWN
// frames that could not be parsed.
type parsedDNP3 struct {
	Direction string `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string `json:"command,omitempty"`   // link function, e.g. REQUEST_LINK_STATUS; UNKNOWN or BAD_CRC when unusable
	Dest      uint16 `json:"dest"`
	Src       uint16 `json:"src"`
	Status    string `json:"status,omitempty"` // write reply name (LINK_STATUS, ACK, NOT_SUPPORTED)
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"` // set on the last frame kept when maxDNP3Frames was reached
}

type dnp3Server struct {
	events []parsedDNP3
	conn   net.Conn
	reads  int
}

var errDNP3Unframed = errors.New("dnp3: stream lost framing")

func dnp3Address() uint16 {
	if viper.IsSet("dnp3.address") {
		return uint16(viper.GetUint32("dnp3.address"))
	}
	return defaultDNP3Address
}

// read returns the next verified frame header. Frames whose data blocks fail
// their CRC are recorded as BAD_CRC and reported with ok=false. A bad start or
// header CRC loses the framing, so it is recorded and returned as an error.
func (s *dnp3Server) read() (hdr dnp3.Header, ok bool, err error) {
	raw := make([]byte, dnp3.HeaderSize)
	n, err := io.ReadFull(s.conn, raw)
	if err != nil {
		if n > 0 {
			s.events = append(s.events, parsedDNP3{Direction: "read", Command: "UNKNOWN", Payload: raw[:n]})
		}
		return hdr, false, err
	}
	s.reads++

	hdr, err = dnp3.ParseHeader(raw)
	if err != nil {
		command := "UNKNOWN"
		if errors.Is(err, dnp3.ErrHeaderCRC) {
			command = "BAD_CRC"
		}
		s.events = append(s.events, parsedDNP3{Direction: "read", Command: command, Payload: raw})
		return hdr, false, errDNP3Unframed
	}

	frame := parsedDNP3{Direction: "read", Command: hdr.Command(), Dest: hdr.Dest, Src: hdr.Src}
	if size := hdr.BodySize(); size > 0 {
		body := make([]byte, size)
		n, err := io.ReadFull(s.conn, body)
		raw = append(raw, body[:n]...)
		if err != nil {
			frame.Payload = raw
			s.events = append(s.events, frame)
			return hdr, false, err
		}
		if _, err := hdr.UserData(body); err != nil {
			frame.Command = "BAD_CRC"
			frame.Payload = raw
			s.events = append(s.events, frame)
			return hdr, false, nil
		}
	}
	frame.Payload = raw
	s.events = append(s.events, frame)
	return hdr, true, nil
}

func (s *dnp3Server) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	reply, _ := dnp3.ParseHeader(data)
	s.events = append(s.events, parsedDNP3{
		Direction: "write",
		Command:   reply.Command(),
		Dest:      reply.Dest,
		Src:       reply.Src,
		Status:    reply.Command(),
		Payload:   data,
	})
	return nil
}

// HandleDNP3 answers DNP3 data link layer frames as a single outstation. Only
// link-layer replies are sent (no application layer, no point data).
func HandleDNP3(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &dnp3Server{events: []parsedDNP3{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("dnp3", conn, md, helpers.FirstOrEmpty[parsedDNP3](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dnp3"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close DNP3 connection", slog.String("protocol", "dnp3"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	logger.Info(
		"DNP3 connection",
		slog.String("handler", "dnp3"),
		slog.String("protocol", "dnp3"),
		slog.String("src_ip", host),
		slog.String("src_port", port),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
	)

	own := dnp3Address()
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "dnp3"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		hdr, ok, err := server.read()
		if err != nil {
			switch {
			case errors.Is(err, errDNP3Unframed):
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				endReason = connection.EndClientClose
			default:
				logger.Debug("Failed to read data", slog.String("protocol", "dnp3"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
			}
			break
		}
		if ok {
			if reply := dnp3.Reply(hdr, own); reply != nil {
				if err := server.write(reply); err != nil {
					logger.Error("Failed to write to connection", slog.String("protocol", "dnp3"), producer.ErrAttr(err))
					endReason = connection.EndWriteError
					return nil
				}
			}
		}
		if server.reads >= maxDNP3Frames {
			for i := len(server.events) - 1; i >= 0; i-- {
				if server.events[i].Direction == "read" {
					server.events[i].Truncated = true
					break
				}
			}
			endReason = connection.EndMaxFrames
			break
		}
	}
	return nil
}
