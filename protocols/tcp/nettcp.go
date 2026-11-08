package tcp

import (
	"bufio"
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
	"github.com/mushorg/glutton/protocols/tcp/nettcp"
)

const (
	maxNetTcpRecords    = 64
	maxNetTcpRecordSize = 64 * 1024
)

// parsedNetTcp is one MS-NMF record of the session.
type parsedNetTcp struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Path        string `json:"path,omitempty"`
	Status      string `json:"status,omitempty"`
	Version     string `json:"version,omitempty"`
	Mode        string `json:"mode,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Fault       string `json:"fault,omitempty"`
	ServerName  string `json:"server_name,omitempty"` // SNI of the ssl-tls upgrade handshake
	TLS         bool   `json:"tls,omitempty"`         // record carried inside the TLS upgrade
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

func parsedFromNetTcpRecord(direction string, rec nettcp.Record) parsedNetTcp {
	p := parsedNetTcp{
		Direction:   direction,
		Command:     rec.Name,
		Path:        rec.Via,
		Version:     rec.Version,
		Mode:        rec.Mode,
		ContentType: rec.ContentType,
		Fault:       rec.Fault,
		Payload:     rec.Raw,
		Truncated:   rec.Truncated,
	}
	if direction == "write" && rec.Fault != "" {
		p.Status = nettcp.FaultName(rec.Fault)
	}
	return p
}

type netTcpServer struct {
	events []parsedNetTcp
	conn   net.Conn
	reader *bufio.Reader
	w      io.Writer
	tls    *connection.TLSInfo // set once the ssl-tls upgrade handshake succeeded
}

func (s *netTcpServer) read() (nettcp.Record, error) {
	rec, err := nettcp.ReadRecord(s.reader, maxNetTcpRecordSize)
	if len(rec.Raw) > 0 {
		// A record cut short by EOF is kept with whatever arrived.
		if err != nil && !errors.Is(err, nettcp.ErrUnknownRecord) {
			rec.Truncated = true
		}
		s.events = append(s.events, s.frame("read", rec))
	}
	return rec, err
}

func (s *netTcpServer) write(data []byte) error {
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, s.frame("write", nettcp.Parse(data)))
	return nil
}

func (s *netTcpServer) frame(direction string, rec nettcp.Record) parsedNetTcp {
	p := parsedFromNetTcpRecord(direction, rec)
	p.TLS = s.tls != nil
	return p
}

// startTLS runs the server side of the application/ssl-tls upgrade over the
// buffered reader and switches the session to the TLS stream. The client's
// handshake bytes are recorded as a read frame.
func (s *netTcpServer) startTLS() error {
	tlsConn, info, err := helpers.TerminateTLSFrom(s.conn, s.reader)
	s.events = append(s.events, parsedNetTcp{
		Direction:  "read",
		Command:    "tls",
		ServerName: info.ServerName,
		Payload:    info.Hello,
		Truncated:  info.Truncated,
	})
	if err != nil {
		return err
	}
	s.tls = info
	s.reader = bufio.NewReader(tlsConn)
	s.w = tlsConn
	return nil
}

// HandleNetTcp takes a net.Conn and answers the .NET Message Framing
// (net.tcp, MS-NMF) preamble, e.g. the Visual Studio remote debugger probe.
func HandleNetTcp(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &netTcpServer{events: []parsedNetTcp{}, conn: conn, reader: bufio.NewReader(conn), w: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if server.tls != nil && md.TLS == nil {
			md.TLS = server.tls
		}
		if err := h.ProduceTCP("nettcp", conn, md, helpers.FirstOrEmpty[parsedNetTcp](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close NetTcp connection", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxNetTcpRecords; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		rec, err := server.read()
		if err != nil {
			if errors.Is(err, nettcp.ErrTooLarge) || errors.Is(err, nettcp.ErrUnknownRecord) || errors.Is(err, nettcp.ErrBadLength) {
				logger.Debug("Malformed NetTcp record", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
				return nil
			}
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logger.Debug("Failed to read data", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if rec.Type == nettcp.RecordVia {
			logger.Info(
				"NetTcp preamble",
				slog.String("handler", "nettcp"),
				slog.String("protocol", "nettcp"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("via", rec.Via),
			)
		}
		reply := nettcp.Respond(rec)
		if reply.StartTLS && server.tls != nil {
			// A second upgrade inside the TLS stream is not valid.
			reply = nettcp.Reply{Data: nettcp.FaultRecord(nettcp.FaultUpgradeInvalid), Close: true}
		}
		if len(reply.Data) > 0 {
			if err := server.write(reply.Data); err != nil {
				logger.Error("Failed to write to connection", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if reply.Close {
			return nil
		}
		if reply.StartTLS {
			if err := server.startTLS(); err != nil {
				logger.Debug("NetTcp TLS upgrade failed", slog.String("protocol", "nettcp"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				return nil
			}
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
