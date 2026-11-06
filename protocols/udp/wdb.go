package udp

import (
	"context"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
	"github.com/mushorg/glutton/protocols/udp/wdb"
)

const maxWDBPayload = 1024

type parsedWDB struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"` // WDB_* procedure, CALL (other program), REPLY or UNKNOWN
	XID       uint32 `json:"xid,omitempty"`
	Program   uint32 `json:"program,omitempty"`
	Version   uint32 `json:"version,omitempty"`
	Procedure uint32 `json:"procedure,omitempty"`
	Auth      string `json:"auth,omitempty"`
	Seq       uint32 `json:"seq,omitempty"` // WDB parameter wrapper sequence number
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

func describeWDBCall(frame *parsedWDB, c *oncrpc.Call) {
	if c == nil {
		return
	}
	frame.XID = c.XID
	switch {
	case c.MsgType == oncrpc.MsgReply:
		frame.Command = "REPLY"
		return
	case c.MsgType != oncrpc.MsgCall || !c.Header:
		return
	}
	frame.Program, frame.Version, frame.Procedure = c.Program, c.Version, c.Procedure
	frame.Command = "CALL"
	if c.Program == wdb.Program {
		frame.Command = wdb.ProcName(c.Procedure)
	}
	if c.Cred {
		frame.Auth = oncrpc.AuthName(c.CredFlavor)
	}
	if w, err := wdb.ParseWrapper(c.Args); err == nil {
		frame.Seq = w.Seq
	}
}

// HandleWDB answers a Wind River WDB (VxWorks debug agent) RPC call on
// udp/17185. PING/CONNECT/DISCONNECT succeed (CONNECT returns a VxWorks 5.5.1
// target description); memory and other procedures get PROC_UNAVAIL.
func HandleWDB(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxWDBPayload))
	copy(payload, data[:len(payload)])

	events := []parsedWDB{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("wdb", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedWDB](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "wdb"), producer.ErrAttr(err))
		}
	}()

	frame := parsedWDB{Direction: "read", Command: "UNKNOWN", Payload: payload, Truncated: len(data) > maxWDBPayload}
	call, err := oncrpc.Parse(payload)
	describeWDBCall(&frame, call)
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse WDB RPC message", slog.String("protocol", "wdb"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("wdb request received",
		slog.String("handler", "wdb"),
		slog.String("protocol", "wdb"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	if frame.Truncated {
		return nil
	}
	body, status := wdb.Reply(call, wdb.DefaultTarget)
	if body == nil {
		return nil
	}
	events = append(events, parsedWDB{Direction: "write", Command: frame.Command, XID: call.XID, Status: status, Payload: body})
	if err := h.ReplyUDP(srcAddr, dstAddr, body); err != nil {
		logger.Error("Failed to send WDB reply", slog.String("protocol", "wdb"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
