package tcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
)

const (
	// rpcbindMaxRecord caps one reassembled RPC message; portmapper calls are
	// well under 1 KiB.
	rpcbindMaxRecord = 16 * 1024
	// rpcbindMaxCalls bounds the calls answered on one connection.
	rpcbindMaxCalls = 32
)

// rpcbindNow is the GETTIME clock; tests replace it.
var rpcbindNow = time.Now

type parsedRPCBind struct {
	Direction     string  `json:"direction,omitempty"`
	Command       string  `json:"command,omitempty"` // PMAPPROC_* / RPCBPROC_*, CALL, REPLY or UNKNOWN
	XID           uint32  `json:"xid,omitempty"`
	Program       uint32  `json:"program,omitempty"`
	Version       uint32  `json:"version,omitempty"`
	Procedure     uint32  `json:"procedure,omitempty"`
	Auth          string  `json:"auth,omitempty"`
	MachineName   string  `json:"machine_name,omitempty"`
	UID           *uint32 `json:"uid,omitempty"`
	GID           *uint32 `json:"gid,omitempty"`
	TargetProgram uint32  `json:"target_program,omitempty"` // GETPORT/GETADDR/SET/UNSET argument
	TargetVersion uint32  `json:"target_version,omitempty"`
	Netid         string  `json:"netid,omitempty"`
	Status        string  `json:"status,omitempty"` // accept/reject outcome on writes
	Payload       []byte  `json:"payload,omitempty"`
	Truncated     bool    `json:"truncated,omitempty"`
}

type rpcbindServer struct {
	events []parsedRPCBind
	conn   net.Conn
	env    oncrpc.Env
}

func (s *rpcbindServer) read() (*oncrpc.Call, error) {
	raw, body, truncated, err := oncrpc.ReadRecord(s.conn, rpcbindMaxRecord)
	if len(raw) == 0 {
		return nil, err
	}
	frame := parsedRPCBind{Direction: "read", Command: "UNKNOWN", Payload: raw, Truncated: truncated}
	call, perr := oncrpc.Parse(body)
	describeRPCCall(&frame, call)
	s.events = append(s.events, frame)
	if err != nil {
		return nil, err
	}
	return call, perr
}

func (s *rpcbindServer) write(xid uint32, command string, body []byte, status string) error {
	data := oncrpc.Frame(body)
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedRPCBind{Direction: "write", Command: command, XID: xid, Status: status, Payload: data})
	return nil
}

// describeRPCCall copies the parsed call header and portmapper arguments into
// a read frame. Partial calls (truncated before the verifier) still get xid /
// program / version / procedure and a best-effort command when Header is set.
func describeRPCCall(frame *parsedRPCBind, c *oncrpc.Call) {
	if c == nil {
		return
	}
	switch c.MsgType {
	case oncrpc.MsgReply:
		frame.XID = c.XID
		frame.Command = "REPLY"
	case oncrpc.MsgCall:
		frame.XID = c.XID
		if !c.Header {
			return
		}
		frame.Command = c.Command()
		frame.Program, frame.Version, frame.Procedure = c.Program, c.Version, c.Procedure
		if c.Cred {
			frame.Auth = oncrpc.AuthName(c.CredFlavor)
			if a := c.AuthSys; a != nil {
				frame.MachineName = a.MachineName
				frame.UID, frame.GID = &a.UID, &a.GID
			}
		}
		if q, err := oncrpc.ParseQuery(c); err == nil && q != nil {
			frame.TargetProgram, frame.TargetVersion, frame.Netid = q.Program, q.Version, q.Netid
		}
	}
}

// HandleRPCBind takes a net.Conn and answers ONC RPC portmapper / rpcbind
// (program 100000, versions 2-4) calls on tcp/111 with a small service list.
func HandleRPCBind(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &rpcbindServer{events: []parsedRPCBind{}, conn: conn, env: oncrpc.Env{
		Mappings: oncrpc.Mappings([]byte(md.TargetIP)),
		LocalIP:  net.ParseIP(md.TargetIP),
	}}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rpcbind", conn, md, helpers.FirstOrEmpty[parsedRPCBind](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close rpcbind connection", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < rpcbindMaxCalls; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		call, err := server.read()
		if err != nil {
			if errors.Is(err, oncrpc.ErrMalformed) || errors.Is(err, oncrpc.ErrRecordTooLarge) || errors.Is(err, oncrpc.ErrTooManyFragments) {
				logger.Debug("Malformed RPC message", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("rpcbind request received",
				slog.String("handler", "rpcbind"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", call.Command()),
			)
		}
		server.env.Now = rpcbindNow()
		body, status := oncrpc.Reply(call, server.env)
		if body == nil {
			continue
		}
		if err := server.write(call.XID, call.Command(), body, status); err != nil {
			logger.Error("Failed to write rpcbind reply", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
