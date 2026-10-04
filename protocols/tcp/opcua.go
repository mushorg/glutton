package tcp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/opcua"
)

const maxOpcuaMessages = 64

type parsedOPCUA struct {
	Direction       string `json:"direction,omitempty"`
	Command         string `json:"command,omitempty"`
	Path            string `json:"path,omitempty"`
	MessageType     string `json:"message_type,omitempty"`
	Service         string `json:"service,omitempty"`
	EndpointURL     string `json:"endpoint_url,omitempty"`
	SecurityPolicy  string `json:"security_policy,omitempty"`
	ApplicationURI  string `json:"application_uri,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	Username        string `json:"username,omitempty"`
	Payload         []byte `json:"payload,omitempty"`
}

type opcuaServer struct {
	events  []parsedOPCUA
	conn    net.Conn
	session *opcua.Session
}

func parsedFromFrame(direction string, f opcua.Frame) parsedOPCUA {
	cmd := f.Service
	if cmd == "" {
		cmd = f.MessageType
	}
	return parsedOPCUA{
		Direction:       direction,
		Command:         cmd,
		Path:            f.EndpointURL,
		MessageType:     f.MessageType,
		Service:         f.Service,
		EndpointURL:     f.EndpointURL,
		SecurityPolicy:  f.SecurityPolicy,
		ApplicationURI:  f.ApplicationURI,
		ApplicationName: f.ApplicationName,
		Username:        f.Username,
		Payload:         f.Payload,
	}
}

func opcuaEndpointURL(conn net.Conn) string {
	host := "1.2.3.4"
	port := "4840"
	if conn != nil && conn.LocalAddr() != nil {
		h, p, err := net.SplitHostPort(conn.LocalAddr().String())
		if err == nil {
			if ip := net.ParseIP(h); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
				host = h
			}
			if p != "" {
				port = p
			}
		}
	}
	return "opc.tcp://" + net.JoinHostPort(host, port)
}

func (s *opcuaServer) read() ([]byte, error) {
	return opcua.ReadMessage(s.conn)
}

func (s *opcuaServer) write(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedFromFrame("write", opcua.Parse(data)))
	return nil
}

// HandleOPCUA takes a net.Conn and does basic OPC UA Binary (opc.tcp) communication.
func HandleOPCUA(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &opcuaServer{
		events:  []parsedOPCUA{},
		conn:    conn,
		session: opcua.NewSession(opcuaEndpointURL(conn)),
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("opcua", conn, md, helpers.FirstOrEmpty[parsedOPCUA](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "opcua"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close OPC UA connection", slog.String("protocol", "opcua"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxOpcuaMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "opcua"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		data, err := server.read()
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logger.Debug("Failed to read data", slog.String("protocol", "opcua"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			break
		}
		frame := opcua.Parse(data)
		server.events = append(server.events, parsedFromFrame("read", frame))

		logger.Info(
			"OPC UA request",
			slog.String("handler", "opcua"),
			slog.String("protocol", "opcua"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("message_type", frame.MessageType),
			slog.String("service", frame.Service),
		)

		reply, err := server.session.Reply(data)
		if err != nil {
			logger.Error("Failed to build OPC UA reply", slog.String("protocol", "opcua"), producer.ErrAttr(err))
			return nil
		}
		if len(reply) == 0 {
			continue
		}
		if err := server.write(reply); err != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "opcua"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
	}
	if i >= maxOpcuaMessages {
		endReason = connection.EndMaxFrames
	}
	return nil
}
