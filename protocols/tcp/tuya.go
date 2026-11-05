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
	"github.com/mushorg/glutton/protocols/tcp/tuya"
)

const (
	// tuyaMaxBody caps the stored frame remainder; real requests are a few
	// hundred bytes.
	tuyaMaxBody = 64 * 1024
	// tuyaMaxRequests bounds the frames recorded for one connection.
	tuyaMaxRequests = 20

	tuyaStatusHeartbeat   = "heartbeat"
	tuyaStatusDataUnvalid = "data-unvalid"
)

type parsedTuya struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // "dp-query", "control", ... or "cmd-0xNN"
	Seq       uint32 `json:"seq,omitempty"`
	Version   string `json:"version,omitempty"`  // plaintext "3.x" body tag, when present
	Checksum  string `json:"checksum,omitempty"` // "crc32-ok" or "mismatch"
	Status    string `json:"status,omitempty"`   // named write outcome
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type tuyaServer struct {
	events []parsedTuya
	conn   net.Conn
}

func (s *tuyaServer) read() (tuya.Frame, error) {
	f, raw, truncated, err := tuya.ReadFrame(s.conn, tuyaMaxBody)
	if len(raw) == 0 {
		return f, err
	}
	frame := parsedTuya{Direction: "read", Payload: raw, Truncated: truncated}
	if len(raw) >= tuya.HeaderLen && !errors.Is(err, tuya.ErrBadPrefix) {
		frame.Command = tuya.CommandName(f.Command)
		frame.Seq = f.Seq
		frame.Version = f.Version
		frame.Checksum = f.Checksum
	}
	s.events = append(s.events, frame)
	return f, err
}

func (s *tuyaServer) write(f tuya.Frame, data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedTuya{
		Direction: "write",
		Command:   tuya.CommandName(f.Command),
		Seq:       f.Seq,
		Status:    status,
		Payload:   data,
	})
	return nil
}

// tuyaResponse picks the device reply: heartbeats are acknowledged, anything
// else gets the plaintext error a device sends when the body does not decrypt
// with its local key (the honeypot has no key).
func tuyaResponse(f tuya.Frame) ([]byte, string) {
	if f.Command == tuya.CmdHeartbeat {
		return tuya.BuildResponse(f.Seq, f.Command, 0, nil), tuyaStatusHeartbeat
	}
	return tuya.BuildResponse(f.Seq, f.Command, 1, tuya.UndecryptableBody), tuyaStatusDataUnvalid
}

// HandleTuya takes a net.Conn and answers the Tuya local LAN protocol on
// tcp/6668. Frames are parsed and recorded; bodies are never decrypted.
func HandleTuya(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &tuyaServer{events: []parsedTuya{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("tuya", conn, md, helpers.FirstOrEmpty[parsedTuya](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "tuya"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Tuya connection", slog.String("protocol", "tuya"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < tuyaMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "tuya"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		f, err := server.read()
		if err != nil {
			switch {
			case errors.Is(err, tuya.ErrBodyTooLarge), errors.Is(err, tuya.ErrBadPrefix), errors.Is(err, tuya.ErrBadLength):
				logger.Debug("Malformed Tuya frame", slog.String("protocol", "tuya"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return nil
			}
			logger.Debug("Failed to read data", slog.String("protocol", "tuya"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("Tuya request received",
				slog.String("handler", "tuya"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", tuya.CommandName(f.Command)),
			)
		}
		resp, status := tuyaResponse(f)
		if err := server.write(f, resp, status); err != nil {
			logger.Error("Failed to write Tuya response", slog.String("protocol", "tuya"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
