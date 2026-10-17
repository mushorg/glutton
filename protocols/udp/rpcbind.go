package udp

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
)

const maxRPCBindPayload = 1024

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

// HandleRPCBind answers an ONC RPC portmapper / rpcbind call (program
// 100000, versions 2-4) in one datagram on udp/111. Replies go only to the
// datagram source and are charged against udp_reply_limit; CALLIT/INDIRECT
// are never forwarded.
func HandleRPCBind(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRPCBindPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRPCBind{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("rpcbind", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRPCBind](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
		}
	}()

	frame := parsedRPCBind{Direction: "read", Command: "UNKNOWN", Payload: payload, Truncated: len(data) > maxRPCBindPayload}
	call, err := oncrpc.Parse(payload)
	describeRPCCall(&frame, call)
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse RPC message", slog.String("protocol", "rpcbind"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("rpcbind request received",
		slog.String("handler", "rpcbind"),
		slog.String("protocol", "rpcbind"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	// A truncated call would be answered from incomplete arguments.
	if frame.Truncated {
		return nil
	}
	seed := dstAddr.IP.String()
	body, status := oncrpc.Reply(call, oncrpc.Env{
		Mappings: oncrpc.Mappings([]byte(seed)),
		LocalIP:  dstAddr.IP,
		Now:      rpcbindNow(),
	})
	if body == nil {
		return nil
	}
	events = append(events, parsedRPCBind{Direction: "write", Command: frame.Command, XID: call.XID, Status: status, Payload: body})
	if err := h.ReplyUDP(srcAddr, dstAddr, body); err != nil {
		logger.Error("Failed to send rpcbind reply", slog.String("protocol", "rpcbind"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
