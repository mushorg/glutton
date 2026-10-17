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
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
)

const (
	// nfsMaxRecord caps one reassembled RPC message; NFS calls we answer carry
	// small arguments.
	nfsMaxRecord = 16 * 1024
	// nfsMaxCalls bounds the calls answered on one connection.
	nfsMaxCalls = 32
)

type parsedNFS struct {
	Direction   string  `json:"direction,omitempty"`
	Command     string  `json:"command,omitempty"` // NFSPROC3_* / NFSPROC4_*, CALL, REPLY or UNKNOWN
	XID         uint32  `json:"xid,omitempty"`
	Program     uint32  `json:"program,omitempty"`
	Version     uint32  `json:"version,omitempty"`
	Procedure   uint32  `json:"procedure,omitempty"`
	Auth        string  `json:"auth,omitempty"`
	MachineName string  `json:"machine_name,omitempty"`
	UID         *uint32 `json:"uid,omitempty"`
	GID         *uint32 `json:"gid,omitempty"`
	Tag         string  `json:"tag,omitempty"`           // NFSv4 COMPOUND tag
	MinorVer    *uint32 `json:"minor_version,omitempty"` // NFSv4 COMPOUND minor version
	Ops         *uint32 `json:"ops,omitempty"`           // NFSv4 COMPOUND operation count
	Status      string  `json:"status,omitempty"`        // accept/reject outcome on writes
	Payload     []byte  `json:"payload,omitempty"`
	Truncated   bool    `json:"truncated,omitempty"`
}

type nfsServer struct {
	events []parsedNFS
	conn   net.Conn
}

func (s *nfsServer) read() (*oncrpc.Call, error) {
	raw, body, truncated, err := oncrpc.ReadRecord(s.conn, nfsMaxRecord)
	if len(raw) == 0 {
		return nil, err
	}
	frame := parsedNFS{Direction: "read", Command: "UNKNOWN", Payload: raw, Truncated: truncated}
	call, perr := oncrpc.Parse(body)
	if perr == nil {
		describeNFSCall(&frame, call)
	}
	s.events = append(s.events, frame)
	if err != nil {
		return nil, err
	}
	return call, perr
}

func (s *nfsServer) write(xid uint32, command string, body []byte, status string) error {
	data := oncrpc.Frame(body)
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedNFS{Direction: "write", Command: command, XID: xid, Status: status, Payload: data})
	return nil
}

// describeNFSCall copies the parsed call header and COMPOUND head into a read
// frame.
func describeNFSCall(frame *parsedNFS, c *oncrpc.Call) {
	frame.Command = oncrpc.NFSCommand(c)
	frame.XID = c.XID
	if c.MsgType != oncrpc.MsgCall {
		return
	}
	frame.Program, frame.Version, frame.Procedure = c.Program, c.Version, c.Procedure
	frame.Auth = oncrpc.AuthName(c.CredFlavor)
	if a := c.AuthSys; a != nil {
		frame.MachineName = a.MachineName
		frame.UID, frame.GID = &a.UID, &a.GID
	}
	if c.Program == oncrpc.ProgNFS && c.Version == 4 && c.Procedure == 1 {
		if tag, minor, ops, err := oncrpc.NFSCompound(c); err == nil {
			frame.Tag, frame.MinorVer, frame.Ops = tag, &minor, &ops
		}
	}
}

// HandleNFS takes a net.Conn and answers ONC RPC calls to the NFS program
// (100003, versions 3 and 4) on tcp/2049. NULL succeeds, file operations fail,
// and other versions get PROG_MISMATCH so scanners can read the version range.
func HandleNFS(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &nfsServer{events: []parsedNFS{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("nfs", conn, md, helpers.FirstOrEmpty[parsedNFS](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "nfs"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close NFS connection", slog.String("protocol", "nfs"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < nfsMaxCalls; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "nfs"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		call, err := server.read()
		if err != nil {
			if errors.Is(err, oncrpc.ErrMalformed) || errors.Is(err, oncrpc.ErrRecordTooLarge) || errors.Is(err, oncrpc.ErrTooManyFragments) {
				logger.Debug("Malformed RPC message", slog.String("protocol", "nfs"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "nfs"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("NFS request received",
				slog.String("handler", "nfs"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", oncrpc.NFSCommand(call)),
			)
		}
		body, status := oncrpc.ReplyNFS(call)
		if body == nil {
			continue
		}
		if err := server.write(call.XID, oncrpc.NFSCommand(call), body, status); err != nil {
			logger.Error("Failed to write NFS reply", slog.String("protocol", "nfs"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
