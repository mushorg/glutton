package tcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/dicom"
)

const (
	maxDicomPDUs = 4096
	// maxDicomCapture bounds the raw bytes kept in one decoded frame.
	maxDicomCapture = 1 << 20
)

// storeDicom persists C-STORE data sets; replaced in tests.
var storeDicom = func(data []byte) error {
	_, err := helpers.Store(data, filepath.Join("payloads", "dicom"))
	return err
}

type parsedDICOM struct {
	Direction              string            `json:"direction,omitempty"`
	Command                string            `json:"command,omitempty"`
	Path                   string            `json:"path,omitempty"`
	Status                 string            `json:"status,omitempty"`
	PDUType                string            `json:"pdu_type,omitempty"`
	CalledAE               string            `json:"called_ae,omitempty"`
	CallingAE              string            `json:"calling_ae,omitempty"`
	ApplicationContext     string            `json:"application_context,omitempty"`
	AbstractSyntaxes       []string          `json:"abstract_syntaxes,omitempty"`
	TransferSyntaxes       []string          `json:"transfer_syntaxes,omitempty"`
	ImplementationClassUID string            `json:"implementation_class_uid,omitempty"`
	ImplementationVersion  string            `json:"implementation_version,omitempty"`
	Username               string            `json:"username,omitempty"`
	MessageID              uint16            `json:"message_id,omitempty"`
	SOPClassUID            string            `json:"sop_class_uid,omitempty"`
	SOPInstanceUID         string            `json:"sop_instance_uid,omitempty"`
	MoveDestination        string            `json:"move_destination,omitempty"`
	Query                  map[string]string `json:"query,omitempty"`
	PayloadHash            string            `json:"payload_hash,omitempty"`
	Payload                []byte            `json:"payload,omitempty"`
	Truncated              bool              `json:"truncated,omitempty"`
}

type dicomServer struct {
	events     []parsedDICOM
	conn       net.Conn
	logger     interfaces.Logger
	associated bool
	calledAE   string
	// accepted presentation context ID → transfer syntax
	contexts  map[byte]string
	assembler dicom.Assembler
	// raw P-DATA-TF bytes of the DIMSE message being reassembled
	pending          []byte
	pendingTruncated bool
}

func (s *dicomServer) read() ([]byte, error) {
	return dicom.ReadPDU(s.conn)
}

func (s *dicomServer) write(data []byte, frame parsedDICOM) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	frame.Direction = "write"
	if frame.PDUType == "" {
		frame.PDUType = dicom.PDUTypeName(data[0])
	}
	if frame.Command == "" {
		frame.Command = frame.PDUType
	}
	frame.Payload = data
	s.events = append(s.events, frame)
	return nil
}

// recordRead appends a read frame for a PDU that carries no further fields.
func (s *dicomServer) recordRead(pdu []byte) {
	name := dicom.PDUTypeName(pdu[0])
	s.events = append(s.events, parsedDICOM{Direction: "read", Command: name, PDUType: name, Payload: pdu})
}

func (s *dicomServer) appendPending(pdu []byte) {
	room := maxDicomCapture - len(s.pending)
	if len(pdu) > room {
		s.pending = append(s.pending, pdu[:room]...)
		s.pendingTruncated = true
		return
	}
	s.pending = append(s.pending, pdu...)
}

// abort sends an A-ABORT (source: service-provider, reason: unexpected PDU).
func (s *dicomServer) abort() error {
	return s.write(dicom.BuildAbort(2, 2), parsedDICOM{})
}

func (s *dicomServer) handleAssociate(pdu []byte) (dicom.AssociateRQ, bool, error) {
	rq, err := dicom.ParseAssociateRQ(pdu)
	s.events = append(s.events, parsedDICOM{
		Direction:              "read",
		Command:                dicom.PDUTypeName(dicom.PDUAssociateRQ),
		Path:                   rq.CalledAE,
		PDUType:                dicom.PDUTypeName(dicom.PDUAssociateRQ),
		CalledAE:               rq.CalledAE,
		CallingAE:              rq.CallingAE,
		ApplicationContext:     rq.ApplicationContext,
		AbstractSyntaxes:       rq.AbstractSyntaxes(),
		TransferSyntaxes:       rq.TransferSyntaxes(),
		ImplementationClassUID: rq.ImplementationClassUID,
		ImplementationVersion:  rq.ImplementationVersion,
		Username:               rq.Username,
		Payload:                pdu,
	})
	if err != nil {
		// rejected-permanent, service-user, no-reason-given
		return rq, false, s.write(dicom.BuildAssociateRJ(1, 1, 1), parsedDICOM{Status: "Rejected"})
	}
	s.associated = true
	s.calledAE = rq.CalledAE
	s.contexts = dicom.AcceptedContexts(rq)
	return rq, true, s.write(dicom.BuildAssociateAC(rq), parsedDICOM{Status: "Accepted"})
}

func (s *dicomServer) handlePData(pdu []byte) error {
	pdvs, err := dicom.ParsePData(pdu)
	if err != nil {
		return err
	}
	s.appendPending(pdu)
	for _, pdv := range pdvs {
		msg, err := s.assembler.Add(pdv)
		if err != nil {
			return err
		}
		if msg == nil {
			continue
		}
		if err := s.handleMessage(msg); err != nil {
			return err
		}
	}
	return nil
}

func (s *dicomServer) handleMessage(msg *dicom.Message) error {
	cmd := msg.Command
	frame := parsedDICOM{
		Direction:       "read",
		Command:         dicom.CommandName(cmd.Field),
		PDUType:         dicom.PDUTypeName(dicom.PDUPData),
		MessageID:       cmd.MessageID,
		SOPClassUID:     cmd.SOPClassUID,
		SOPInstanceUID:  cmd.SOPInstanceUID,
		MoveDestination: cmd.MoveDestination,
		Payload:         s.pending,
		Truncated:       s.pendingTruncated || msg.Truncated,
	}
	s.pending, s.pendingTruncated = nil, false
	if cmd.Field == dicom.CStoreRQ && len(msg.DataSet) > 0 {
		frame.PayloadHash = helpers.SHA256Hex(msg.DataSet)
		if err := storeDicom(msg.DataSet); err != nil {
			s.logger.Error("Failed to store data set", slog.String("protocol", "dicom"), producer.ErrAttr(err))
		}
	}
	ts := s.contexts[msg.ContextID]
	switch cmd.Field {
	case dicom.CFindRQ, dicom.CGetRQ, dicom.CMoveRQ:
		// the identifier holds the search keys; decode what we can
		elems, _ := dicom.ParseDataSet(msg.DataSet, ts)
		frame.Query = dicom.QueryMap(elems)
	}
	s.events = append(s.events, frame)

	if cmd.Field == dicom.CFindRQ {
		for _, r := range dicom.FindReplies(cmd, msg.DataSet, ts, s.calledAE) {
			if err := s.reply(msg.ContextID, r); err != nil {
				return err
			}
		}
		return nil
	}
	resp, ok := dicom.Response(cmd)
	if !ok {
		return nil
	}
	return s.reply(msg.ContextID, dicom.Reply{Command: resp})
}

// reply sends a DIMSE response command, and its data set if any, in one P-DATA-TF.
func (s *dicomServer) reply(contextID byte, r dicom.Reply) error {
	pdvs := []dicom.PDV{{ContextID: contextID, Command: true, Last: true, Data: dicom.EncodeCommand(r.Command)}}
	if r.DataSet != nil {
		pdvs = append(pdvs, dicom.PDV{ContextID: contextID, Last: true, Data: r.DataSet})
	}
	return s.write(dicom.BuildPDataPDVs(pdvs...), parsedDICOM{
		Command:     dicom.CommandName(r.Command.Field),
		Status:      dicom.StatusName(r.Command.Status),
		MessageID:   r.Command.RespondedTo,
		SOPClassUID: r.Command.SOPClassUID,
	})
}

// HandleDICOM takes a net.Conn and does basic DICOM Upper Layer communication:
// it accepts any association, answers C-ECHO and C-STORE with success (storing
// the data sets), answers Q/R C-FIND with matches from a synthetic archive and
// refuses C-GET/C-MOVE.
func HandleDICOM(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &dicomServer{events: []parsedDICOM{}, conn: conn, logger: logger}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("dicom", conn, md, helpers.FirstOrEmpty[parsedDICOM](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dicom"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close DICOM connection", slog.String("protocol", "dicom"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	i := 0
	for ; i < maxDicomPDUs; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "dicom"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		pdu, err := server.read()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				logger.Debug("Failed to read data", slog.String("protocol", "dicom"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			if errors.Is(err, dicom.ErrPDUTooLarge) {
				endReason = connection.EndReadError
				if err := server.abort(); err != nil {
					logger.Debug("Failed to write abort", slog.String("protocol", "dicom"), producer.ErrAttr(err))
				}
			}
			return nil
		}

		var werr error
		done := false
		switch {
		case pdu[0] == dicom.PDUAssociateRQ && !server.associated:
			var rq dicom.AssociateRQ
			var accepted bool
			rq, accepted, werr = server.handleAssociate(pdu)
			done = !accepted
			logger.Info(
				"DICOM association",
				slog.String("handler", "dicom"),
				slog.String("protocol", "dicom"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("called_ae", rq.CalledAE),
				slog.String("calling_ae", rq.CallingAE),
			)
		case pdu[0] == dicom.PDUPData && server.associated:
			if err := server.handlePData(pdu); err != nil {
				logger.Debug("Malformed P-DATA-TF", slog.String("protocol", "dicom"), producer.ErrAttr(err))
				server.recordRead(pdu)
				werr, done = server.abort(), true
			}
		case pdu[0] == dicom.PDUReleaseRQ:
			server.recordRead(pdu)
			werr, done = server.write(dicom.BuildReleaseRP(), parsedDICOM{}), true
		case pdu[0] == dicom.PDUAbort:
			server.recordRead(pdu)
			done = true
		default:
			// unexpected PDU for the association state
			server.recordRead(pdu)
			werr, done = server.abort(), true
		}
		if werr != nil {
			logger.Error("Failed to write to connection", slog.String("protocol", "dicom"), producer.ErrAttr(werr))
			endReason = connection.EndWriteError
			return nil
		}
		if done {
			return nil
		}
	}
	if i >= maxDicomPDUs {
		endReason = connection.EndMaxFrames
	}
	return nil
}
