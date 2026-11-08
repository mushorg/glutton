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
	"github.com/mushorg/glutton/protocols/tcp/epm"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

// maxDCERPCPDUs bounds the PDUs answered on one connection; a lookup is a
// bind plus one or two requests.
const maxDCERPCPDUs = 32

// nca status codes (MS-RPCE 2.2.2.11, DCE 1.1 Appendix E).
const (
	ncaOpRangeError = 0x1c010002 // nca_s_op_rng_error
	ncaUnknownIf    = 0x1c010003 // nca_s_unknown_if
)

type parsedDCERPC struct {
	Direction              string  `json:"direction,omitempty"`                // "read" (from attacker) or "write" (from honeypot)
	DCERPC                 string  `json:"dcerpc,omitempty"`                   // PDU type (DCERPC_BIND, DCERPC_REQUEST, DCERPC_RESPONSE, ...)
	Command                string  `json:"command,omitempty"`                  // reads: EPM operation (ept_lookup) or the PDU type
	CallID                 uint32  `json:"call_id,omitempty"`                  // call_id, echoed in the reply
	Interface              string  `json:"interface,omitempty"`                // bound abstract syntax UUID
	InterfaceVersion       string  `json:"interface_version,omitempty"`        // bound abstract syntax version
	Opnum                  *uint16 `json:"opnum,omitempty"`                    // request opnum
	TargetInterface        string  `json:"target_interface,omitempty"`         // interface asked about in ept_lookup / ept_map
	TargetInterfaceVersion string  `json:"target_interface_version,omitempty"` // its version
	Status                 string  `json:"status,omitempty"`                   // writes: bind_ack, EPT_S_NOT_REGISTERED, nca_s_* fault
	Payload                []byte  `json:"payload,omitempty"`                  // raw PDU as seen on the wire
}

type dcerpcServer struct {
	events   []parsedDCERPC
	conn     net.Conn
	secAddr  string
	contexts map[uint16]smb.BindContext
}

// readPDU reads one connection-oriented PDU. ok is false when the bytes are
// not a little-endian DCE/RPC v5.0 PDU; whatever was read is still returned.
// A client hanging up mid-PDU reports io.EOF.
func (s *dcerpcServer) readPDU() (pdu []byte, hdr smb.DCERPCHeader, ok bool, err error) {
	head := make([]byte, smb.HeaderLen)
	if n, err := io.ReadFull(s.conn, head); err != nil {
		return head[:n], hdr, false, eofIfShort(err)
	}
	hdr, ok = smb.ParseDCERPCHeader(head)
	if !ok || head[1] != 0 || !hdr.LittleEn || int(hdr.FragLen) < smb.HeaderLen {
		return head, hdr, false, nil
	}
	pdu = make([]byte, hdr.FragLen)
	copy(pdu, head)
	if n, err := io.ReadFull(s.conn, pdu[smb.HeaderLen:]); err != nil {
		return pdu[:smb.HeaderLen+n], hdr, false, eofIfShort(err)
	}
	return pdu, hdr, true, nil
}

func eofIfShort(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

func (s *dcerpcServer) write(data []byte, frame parsedDCERPC) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.DCERPC = smb.DCERPCName(data[2])
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

// handleBind accepts every offered presentation context, as rpcss does for
// the interfaces it serves on 135, echoing the call_id.
func (s *dcerpcServer) handleBind(pdu []byte, hdr smb.DCERPCHeader, frame *parsedDCERPC) ([]byte, string, bool) {
	ctxs, ok := smb.ParseBind(pdu)
	if !ok {
		return nil, "", false
	}
	frame.Interface, frame.InterfaceVersion = ctxs[0].InterfaceUUID(), ctxs[0].InterfaceVersion()
	for _, c := range ctxs {
		s.contexts[c.ContextID] = c
	}
	return smb.BuildBindAck(hdr.CallID, s.secAddr, ctxs), "bind_ack", true
}

// handleRequest answers ept_lookup and ept_map with an empty result and
// faults everything else, echoing call_id and p_cont_id.
func (s *dcerpcServer) handleRequest(pdu []byte, hdr smb.DCERPCHeader, frame *parsedDCERPC) ([]byte, string, bool) {
	opnum, ctxID, stub, ok := smb.ParseRequest(pdu)
	if !ok {
		return nil, "", false
	}
	frame.Opnum = &opnum
	bound, isBound := s.contexts[ctxID]
	if !isBound {
		return smb.BuildFaultFor(hdr.CallID, ctxID, ncaUnknownIf), "nca_s_unknown_if", true
	}
	frame.Interface, frame.InterfaceVersion = bound.InterfaceUUID(), bound.InterfaceVersion()
	if frame.Interface != epm.UUID {
		return smb.BuildFaultFor(hdr.CallID, ctxID, smb.FaultNDR), "nca_s_fault_ndr", true
	}
	name := epm.OpName(opnum)
	if name == "" {
		return smb.BuildFaultFor(hdr.CallID, ctxID, ncaOpRangeError), "nca_s_op_rng_error", true
	}
	frame.Command = name
	var req epm.Request
	switch opnum {
	case epm.OpLookup:
		req, ok = epm.ParseLookup(stub)
	case epm.OpMap:
		req, ok = epm.ParseMap(stub)
	default:
		ok = false
	}
	frame.TargetInterface, frame.TargetInterfaceVersion = req.Interface, req.InterfaceVersion
	if !ok {
		return smb.BuildFaultFor(hdr.CallID, ctxID, smb.FaultNDR), "nca_s_fault_ndr", true
	}
	return smb.BuildResponse(hdr.CallID, ctxID, epm.BuildEmptyResult(req.Max)), "EPT_S_NOT_REGISTERED", true
}

// HandleDCERPC takes a net.Conn and answers connection-oriented DCE/RPC as
// the Windows endpoint mapper on tcp/135 does: binds are accepted,
// ept_lookup / ept_map report no registered endpoints, and other calls fault.
// No RPC service is emulated.
func HandleDCERPC(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &dcerpcServer{
		events:   []parsedDCERPC{},
		conn:     conn,
		secAddr:  strconv.Itoa(int(md.TargetPort)),
		contexts: map[uint16]smb.BindContext{},
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("dcerpc", conn, md, helpers.FirstOrEmpty[parsedDCERPC](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dcerpc"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close DCE/RPC connection", slog.String("protocol", "dcerpc"), producer.ErrAttr(err))
		}
	}()

	for range maxDCERPCPDUs {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "dcerpc"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		pdu, hdr, ok, err := server.readPDU()
		if len(pdu) > 0 {
			frame := parsedDCERPC{Direction: "read", Payload: pdu}
			if ok {
				frame.DCERPC, frame.Command, frame.CallID = smb.DCERPCName(hdr.PType), smb.DCERPCName(hdr.PType), hdr.CallID
			}
			var reply []byte
			var status string
			if ok {
				switch hdr.PType {
				case smb.PTypeBind:
					reply, status, ok = server.handleBind(pdu, hdr, &frame)
				case smb.PTypeRequest:
					reply, status, ok = server.handleRequest(pdu, hdr, &frame)
				default:
					ok = false
				}
			}
			server.events = append(server.events, frame)
			if ok {
				if werr := server.write(reply, parsedDCERPC{CallID: hdr.CallID, Status: status}); werr != nil {
					logger.Debug("Failed to write response", slog.String("protocol", "dcerpc"), producer.ErrAttr(werr))
					endReason = connection.EndWriteError
					return nil
				}
			}
		}
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "dcerpc"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if !ok {
			// not a PDU this endpoint answers: rpcss drops the association
			logger.Debug("Unhandled DCE/RPC PDU", slog.String("protocol", "dcerpc"), slog.Int("bytes", len(pdu)))
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
