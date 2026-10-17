package tcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/hl7"
)

const (
	// hl7MaxMessage caps one stored message; ADT/ORU messages are a few KB.
	hl7MaxMessage = 1 << 20
	// hl7MaxMessages bounds the messages recorded for one connection.
	hl7MaxMessages = 100
	// hl7ReaderSize lets a bare (unframed) message arrive as one chunk.
	hl7ReaderSize = 64 * 1024
)

// hl7Now and hl7ControlID stamp the ACK; vars so tests are deterministic.
var (
	hl7Now       = time.Now
	hl7ControlID = func() string { return strconv.FormatUint(rand.Uint64N(1e10), 10) }
)

type parsedHL7 struct {
	Direction            string   `json:"direction,omitempty"`
	Command              string   `json:"command,omitempty"` // MSH-9 message type, e.g. ADT^A01
	ControlID            string   `json:"control_id,omitempty"`
	Version              string   `json:"version,omitempty"`
	SendingApplication   string   `json:"sending_application,omitempty"`
	SendingFacility      string   `json:"sending_facility,omitempty"`
	ReceivingApplication string   `json:"receiving_application,omitempty"`
	ReceivingFacility    string   `json:"receiving_facility,omitempty"`
	Security             string   `json:"security,omitempty"` // MSH-8, as the client sent it
	Segments             []string `json:"segments,omitempty"`
	Framing              string   `json:"framing,omitempty"` // mllp or raw
	Status               string   `json:"status,omitempty"`  // MSA-1 on writes: AA, AE, AR
	Payload              []byte   `json:"payload,omitempty"`
	Truncated            bool     `json:"truncated,omitempty"`
}

type hl7Server struct {
	events []parsedHL7
	conn   net.Conn
	reader *bufio.Reader
}

func hl7Framing(framed bool) string {
	if framed {
		return "mllp"
	}
	return "raw"
}

// hl7Request is one received message as the reply needs it.
type hl7Request struct {
	header hl7.Header
	noMSH  bool // the message did not start with an MSH segment
	framed bool
}

func (s *hl7Server) read() (hl7Request, error) {
	raw, msg, framed, truncated, err := hl7.ReadMessage(s.reader, hl7MaxMessage)
	if len(raw) == 0 {
		return hl7Request{}, err
	}
	hdr, perr := hl7.ParseMSH(msg)
	s.events = append(s.events, parsedHL7{
		Direction:            "read",
		Command:              hdr.MessageType(),
		ControlID:            hdr.ControlID,
		Version:              hdr.Version,
		SendingApplication:   hdr.SendingApplication,
		SendingFacility:      hdr.SendingFacility,
		ReceivingApplication: hdr.ReceivingApplication,
		ReceivingFacility:    hdr.ReceivingFacility,
		Security:             hdr.Security,
		Segments:             hl7.SegmentIDs(msg, hdr.FieldSep),
		Framing:              hl7Framing(framed),
		Payload:              raw,
		Truncated:            truncated,
	})
	return hl7Request{header: hdr, noMSH: perr != nil, framed: framed}, err
}

func (s *hl7Server) write(req hl7Request, ack hl7.Ack) error {
	data := hl7.BuildACK(req.header, ack)
	if req.framed {
		data = hl7.Frame(data)
	}
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	hdr := hl7.AckHeader(req.header, ack)
	s.events = append(s.events, parsedHL7{
		Direction:            "write",
		Command:              hdr.MessageType(),
		ControlID:            hdr.ControlID,
		Version:              hdr.Version,
		SendingApplication:   hdr.SendingApplication,
		SendingFacility:      hdr.SendingFacility,
		ReceivingApplication: hdr.ReceivingApplication,
		ReceivingFacility:    hdr.ReceivingFacility,
		Framing:              hl7Framing(req.framed),
		Status:               ack.Code,
		Payload:              data,
	})
	return nil
}

// hl7Reply picks the acknowledgement code for a request, the way an
// interface engine in original-acknowledgement mode answers.
func hl7Reply(req hl7Request) hl7.Ack {
	ack := hl7.Ack{
		Code:      "AA",
		ControlID: hl7ControlID(),
		Timestamp: hl7Now().Format("20060102150405.000-0700"),
	}
	switch {
	case req.noMSH:
		ack.Code, ack.ErrorCode = "AR", hl7.ErrorSegmentSequence
	case req.header.MessageCode == "" || req.header.ControlID == "":
		ack.Code, ack.ErrorCode = "AE", hl7.ErrorRequiredField
	}
	return ack
}

// HandleHL7 takes a net.Conn and answers HL7 v2 over MLLP (tcp/2575), the
// interface-engine port hospital systems exchange ADT/ORM/ORU messages on.
// Every message gets an original-mode ACK; queries never get patient data.
// Inspired by medpot (github.com/schmalle/medpot), written from the HL7 spec.
func HandleHL7(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &hl7Server{events: []parsedHL7{}, conn: conn, reader: bufio.NewReaderSize(conn, hl7ReaderSize)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("hl7", conn, md, helpers.FirstOrEmpty[parsedHL7](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "hl7"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close HL7 connection", slog.String("protocol", "hl7"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < hl7MaxMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "hl7"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			if errors.Is(err, hl7.ErrTooLarge) {
				logger.Debug("HL7 message too large", slog.String("protocol", "hl7"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "hl7"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("HL7 message received",
				slog.String("handler", "hl7"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("message_type", req.header.MessageType()),
			)
		}
		if err := server.write(req, hl7Reply(req)); err != nil {
			logger.Error("Failed to write HL7 response", slog.String("protocol", "hl7"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
