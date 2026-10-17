package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/pcom"
)

const maxPCOMFrames = 64

// pcomIdentity is the persona in ID replies; it is random per process so
// sensors differ, and tests swap it.
var pcomIdentity = sync.OnceValue(pcom.RandomIdentity)

type parsedPCOM struct {
	Direction string `json:"direction,omitempty"`
	Mode      string `json:"mode,omitempty"`      // "ascii" or "binary"
	TID       uint16 `json:"tid,omitempty"`       // PCOM/TCP transaction id
	Unit      string `json:"unit,omitempty"`      // unit id the client addressed
	Command   string `json:"command,omitempty"`   // ASCII command (ID) or binary command byte (0x0c)
	Status    string `json:"status,omitempty"`    // named write outcome: id, error, echo
	Payload   []byte `json:"payload,omitempty"`   // raw bytes as seen on the wire
	Truncated bool   `json:"truncated,omitempty"` // set when the length field exceeded the cap
}

type pcomServer struct {
	events []parsedPCOM
	conn   net.Conn
}

func (s *pcomServer) write(frame parsedPCOM, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

// HandlePCOM answers Unitronics PCOM over TCP: an ASCII ID command gets a
// PLC identity, every other ASCII command an error reply, and binary
// messages an empty echo reply.
func HandlePCOM(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &pcomServer{events: []parsedPCOM{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("pcom", conn, md, helpers.FirstOrEmpty[parsedPCOM](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "pcom"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close PCOM connection", slog.String("protocol", "pcom"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxPCOMFrames; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "pcom"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		hdr, msg, raw, err := pcom.ReadFrame(conn)
		if err != nil {
			if len(raw) > 0 {
				server.events = append(server.events, parsedPCOM{
					Direction: "read",
					Payload:   raw,
					Truncated: errors.Is(err, pcom.ErrTooLarge),
				})
			}
			switch {
			case errors.Is(err, pcom.ErrBadMode), errors.Is(err, pcom.ErrBadLen), errors.Is(err, pcom.ErrTooLarge):
				endReason = connection.EndReadError
			case errors.Is(err, io.ErrUnexpectedEOF):
				// the client closed mid-frame
				endReason = connection.EndClientClose
			default:
				endReason = connection.EndReasonFromRead(err)
			}
			if !errors.Is(err, io.EOF) {
				logger.Debug("Failed to read data", slog.String("protocol", "pcom"), producer.ErrAttr(err))
			}
			return nil
		}

		read := parsedPCOM{Direction: "read", TID: hdr.TID, Payload: raw}
		var reply []byte
		write := parsedPCOM{TID: hdr.TID}
		if hdr.Mode == pcom.ModeASCII {
			read.Mode, write.Mode = "ascii", "ascii"
			req, ok := pcom.ParseASCII(msg)
			read.Unit, read.Command = req.Unit, req.Command
			write.Unit, write.Command = req.Unit, req.Command
			switch {
			case ok && req.Command == "ID":
				reply, write.Status = pcom.IDReply(req.Unit, pcomIdentity()), "id"
			case ok:
				reply, write.Status = pcom.ErrorReply(req.Unit, pcom.ErrCodeUnrecognized), "error"
			default:
				reply, write.Status = pcom.ErrorReply("00", pcom.ErrCodeUnrecognized), "error"
			}
		} else {
			read.Mode, write.Mode = "binary", "binary"
			if req, ok := pcom.ParseBinary(msg); ok {
				read.Unit = strconv.Itoa(int(req.Unit))
				read.Command = fmt.Sprintf("0x%02x", req.Command)
				write.Unit, write.Command = read.Unit, read.Command
				reply, write.Status = pcom.BinaryReply(msg), "echo"
			}
		}
		server.events = append(server.events, read)
		logger.Info("PCOM request",
			slog.String("handler", "pcom"),
			slog.String("protocol", "pcom"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("mode", read.Mode),
			slog.String("command", read.Command),
		)
		if reply == nil {
			// a binary message that does not parse gets no reply
			continue
		}

		if err := server.write(write, pcom.Build(pcom.Header{TID: hdr.TID, Mode: hdr.Mode}, reply)); err != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "pcom"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
