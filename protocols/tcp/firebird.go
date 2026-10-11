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
	"github.com/mushorg/glutton/protocols/tcp/firebird"
)

const (
	// maxFirebirdPackets bounds a session: op_connect plus a few login
	// attempts on the same connection.
	maxFirebirdPackets = 16
	// maxFirebirdPacketLen caps one operation; an op_attach is a few
	// hundred bytes.
	maxFirebirdPacketLen = 16 * 1024
)

type firebirdProtocol struct {
	Version uint32 `json:"version"`
	Arch    uint32 `json:"arch"`
	MinType uint32 `json:"min_type"`
	MaxType uint32 `json:"max_type"`
	Weight  uint32 `json:"weight"`
}

type parsedFirebird struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Path      string `json:"path,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// op_connect
	Operation  string             `json:"operation,omitempty"`
	ClientArch uint32             `json:"client_arch,omitempty"`
	Login      string             `json:"login,omitempty"`
	AuthPlugin string             `json:"auth_plugin,omitempty"`
	Protocols  []firebirdProtocol `json:"protocols,omitempty"`
	// op_connect user identification and attach parameters
	OSUser     string `json:"os_user,omitempty"`
	ClientHost string `json:"client_host,omitempty"`
	// op_attach, op_create, op_service_attach (password also CNCT_passwd of
	// op_connect); passwords are guessing attempts and recorded as sent
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Role          string `json:"role,omitempty"`
	Charset       string `json:"charset,omitempty"`
	ProcessID     uint32 `json:"process_id,omitempty"`
	ProcessName   string `json:"process_name,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	// write
	ProtocolVersion uint32 `json:"protocol_version,omitempty"`
	ErrorCode       uint32 `json:"error_code,omitempty"`
}

type firebirdServer struct {
	events []parsedFirebird
	conn   net.Conn
	reader *bufio.Reader
}

func (s *firebirdServer) read() (firebird.Packet, error) {
	pkt, err := firebird.ReadPacket(s.reader, maxFirebirdPacketLen)
	if len(pkt.Raw) > 0 {
		s.events = append(s.events, parsedFirebird{
			Direction: "read",
			Command:   firebird.OpName(pkt.Op),
			Payload:   pkt.Raw,
			Truncated: err != nil && !errors.Is(err, firebird.ErrUnknownOp),
		})
	}
	return pkt, err
}

func (s *firebirdServer) write(f parsedFirebird) error {
	if _, err := s.conn.Write(f.Payload); err != nil {
		return err
	}
	f.Direction = "write"
	s.events = append(s.events, f)
	return nil
}

func (s *firebirdServer) lastRead() *parsedFirebird {
	return &s.events[len(s.events)-1]
}

// handleConnect records the op_connect and accepts or rejects it. done is
// true when the protocol was rejected.
func (s *firebirdServer) handleConnect(c firebird.Connect) (done bool, err error) {
	f := s.lastRead()
	f.Path = c.File
	f.Operation = firebird.OpName(c.Operation)
	f.ClientArch = c.ClientArch
	f.OSUser = c.OSUser
	f.ClientHost = c.Host
	f.Password = c.Password
	f.Login = c.Login
	f.AuthPlugin = c.Plugin
	for _, p := range c.Protocols {
		f.Protocols = append(f.Protocols, firebirdProtocol{
			Version: firebird.VersionNumber(p.Version),
			Arch:    p.Arch,
			MinType: p.MinType,
			MaxType: p.MaxType,
			Weight:  p.Weight,
		})
	}
	p, ok := firebird.SelectProtocol(c.Protocols)
	if !ok {
		return true, s.write(parsedFirebird{Status: "reject", Payload: firebird.BuildReject()})
	}
	return false, s.write(parsedFirebird{
		Status:          "accept",
		Payload:         firebird.BuildAccept(p),
		ProtocolVersion: firebird.VersionNumber(p.Version),
	})
}

// handleAttach records the attach parameters and rejects the login.
func (s *firebirdServer) handleAttach(a firebird.Attach) error {
	f := s.lastRead()
	f.Path = a.File
	f.Username = a.Username
	f.Password = a.Password
	f.Role = a.Role
	f.Charset = a.Charset
	f.ProcessID = a.ProcessID
	f.ProcessName = a.ProcessName
	f.ClientVersion = a.ClientVersion
	f.ClientHost = a.HostName
	f.OSUser = a.OSUser
	return s.write(parsedFirebird{
		Status:    "login_failed",
		Payload:   firebird.BuildLoginFailed(),
		ErrorCode: firebird.ISCLogin,
	})
}

// HandleFirebird answers the Firebird remote protocol like a Firebird 2.5
// server: it accepts the op_connect and rejects every attach with isc_login,
// recording the client's protocols and login parameters.
func HandleFirebird(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &firebirdServer{events: []parsedFirebird{}, conn: conn, reader: bufio.NewReader(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("firebird", conn, md, helpers.FirstOrEmpty[parsedFirebird](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "firebird"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Firebird connection", slog.String("protocol", "firebird"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	connected := false

	for i := 0; ; i++ {
		if i == maxFirebirdPackets {
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "firebird"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		pkt, err := server.read()
		if err != nil {
			switch {
			case errors.Is(err, firebird.ErrUnknownOp):
				logger.Debug("Unsupported Firebird operation", slog.String("protocol", "firebird"), slog.String("command", firebird.OpName(pkt.Op)))
			case errors.Is(err, firebird.ErrTooLong), errors.Is(err, firebird.ErrMalformed):
				logger.Debug("Invalid Firebird packet", slog.String("protocol", "firebird"), producer.ErrAttr(err))
				endReason = connection.EndReadError
			default:
				if !errors.Is(err, io.EOF) {
					logger.Debug("Failed to read Firebird packet", slog.String("protocol", "firebird"), producer.ErrAttr(err))
				}
				endReason = connection.EndReasonFromRead(err)
			}
			return nil
		}

		var done bool
		switch {
		case pkt.Op == firebird.OpConnect && !connected:
			done, err = server.handleConnect(pkt.Connect)
			connected = true
		case connected && (pkt.Op == firebird.OpAttach || pkt.Op == firebird.OpCreate || pkt.Op == firebird.OpServiceAttach):
			logger.Info(
				"Firebird login attempt",
				slog.String("handler", "firebird"),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("command", firebird.OpName(pkt.Op)),
				slog.String("path", pkt.Attach.File),
				slog.String("username", pkt.Attach.Username),
			)
			err = server.handleAttach(pkt.Attach)
		case pkt.Op == firebird.OpDummy:
			// keepalive; the server does not answer it
		default:
			// op_detach/op_disconnect/op_exit, or anything out of order
			return nil
		}
		if err != nil {
			logger.Error("Failed to write Firebird response", slog.String("protocol", "firebird"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if done {
			return nil
		}
	}
}
