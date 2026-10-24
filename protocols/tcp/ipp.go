package tcp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/ipp"
)

const (
	// ippMaxBody caps the stored request body (IPP attributes plus document).
	ippMaxBody = 1 << 20
	// ippMaxRequests bounds the requests answered on one connection.
	ippMaxRequests = 100
)

// storeIPP persists print documents and PPDs; replaced in tests.
var storeIPP = func(data []byte) (string, error) {
	return helpers.Store(data, filepath.Join("payloads", "ipp"))
}

// ippJobs numbers jobs across connections like a single queue; tests reset it.
var ippJobs atomic.Int32

type parsedIPP struct {
	Direction      string          `json:"direction,omitempty"`
	Command        string          `json:"command,omitempty"` // IPP operation, or the HTTP method for non-IPP requests
	Method         string          `json:"method,omitempty"`  // HTTP method
	Path           string          `json:"path,omitempty"`    // HTTP request path
	Status         string          `json:"status,omitempty"`  // HTTP status code on writes
	IPPStatus      string          `json:"ipp_status,omitempty"`
	Version        string          `json:"version,omitempty"` // IPP version of the request
	RequestID      uint32          `json:"request_id,omitempty"`
	JobID          int32           `json:"job_id,omitempty"`
	UserAgent      string          `json:"user_agent,omitempty"`
	Username       string          `json:"username,omitempty"` // HTTP Basic credentials
	Password       string          `json:"password,omitempty"`
	RequestingUser string          `json:"requesting_user,omitempty"` // requesting-user-name
	PrinterURI     string          `json:"printer_uri,omitempty"`
	JobName        string          `json:"job_name,omitempty"`
	DocumentFormat string          `json:"document_format,omitempty"`
	DocumentURI    string          `json:"document_uri,omitempty"` // Print-URI / Send-URI; never fetched
	DeviceURI      string          `json:"device_uri,omitempty"`   // CUPS-Add-Modify-Printer
	PPDName        string          `json:"ppd_name,omitempty"`
	Attributes     []ipp.Attribute `json:"attributes,omitempty"`
	PayloadHash    string          `json:"payload_hash,omitempty"` // SHA-256 of the stored document
	Payload        []byte          `json:"payload,omitempty"`
	Truncated      bool            `json:"truncated,omitempty"`
}

type ippServer struct {
	events  []parsedIPP
	conn    net.Conn
	reader  *bufio.Reader
	persona ipp.Persona
	// now dates the replies; tests pin it.
	now func() time.Time
}

func newIPPServer(conn net.Conn) *ippServer {
	return &ippServer{
		events:  []parsedIPP{},
		conn:    conn,
		reader:  bufio.NewReader(conn),
		persona: ipp.DefaultPersona,
		now:     time.Now,
	}
}

func (s *ippServer) write(frame parsedIPP) error {
	if _, err := s.conn.Write(frame.Payload); err != nil {
		return err
	}
	frame.Direction = "write"
	s.events = append(s.events, frame)
	return nil
}

// ippReply is one response and how it is recorded.
type ippReply struct {
	code      int
	ippStatus string
	requestID uint32
	jobID     int32
	data      []byte
}

// ippRequestedJob returns the job a request names by job-id or job-uri.
func ippRequestedJob(msg ipp.Message) int32 {
	id := msg.Get("operation", "job-id")
	if id == "" {
		if uri := msg.Get("operation", "job-uri"); uri != "" {
			id = uri[strings.LastIndex(uri, "/")+1:]
		}
	}
	n, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		return 0
	}
	return int32(n)
}

// respondIPP answers one decoded IPP request as the CUPS queue.
func (s *ippServer) respondIPP(req ipp.Request, msg ipp.Message, authed bool) ippReply {
	now := s.now()
	keepAlive := req.KeepAlive()
	if ipp.RequiresAuth(msg.Operation) && !authed {
		return ippReply{code: http.StatusUnauthorized, requestID: msg.RequestID, data: ipp.Unauthorized(s.persona, now, keepAlive)}
	}

	host := ipp.URIHost(req.Header("Host"))
	resp := ipp.Response{Major: msg.Major, Minor: msg.Minor, Status: ipp.StatusOK, RequestID: msg.RequestID}
	message := ""
	var jobID int32
	var extra []ipp.Group
	known := func(id int32) bool { return id > 0 && id <= ippJobs.Load() }

	switch {
	case msg.Major < 1 || msg.Major > 2:
		resp.Major, resp.Minor = 2, 0
		resp.Status = ipp.StatusVersionNotSupported
		message = "Bad request version number " + msg.Version() + "."
	case ipp.RequiresAuth(msg.Operation):
		// authenticated admin operation: accept it
	default:
		switch msg.Operation {
		case ipp.OpGetPrinterAttributes, ipp.OpCUPSGetDefault, ipp.OpCUPSGetPrinters:
			extra = append(extra, ipp.Group{Tag: ipp.TagPrinter,
				Attrs: ipp.PrinterAttributes(s.persona, host, now, msg.Values("operation", "requested-attributes"))})
		case ipp.OpValidateJob, ipp.OpValidateDocument, ipp.OpGetJobs, ipp.OpIdentifyPrinter, ipp.OpCancelMyJobs:
		case ipp.OpPrintJob, ipp.OpPrintURI:
			jobID = ippJobs.Add(1)
			extra = append(extra, ipp.Group{Tag: ipp.TagJob,
				Attrs: ipp.JobAttributes(s.persona, host, jobID, ipp.JobProcessing, "job-printing")})
		case ipp.OpCreateJob:
			jobID = ippJobs.Add(1)
			extra = append(extra, ipp.Group{Tag: ipp.TagJob,
				Attrs: ipp.JobAttributes(s.persona, host, jobID, ipp.JobPending, "job-incoming")})
		case ipp.OpSendDocument, ipp.OpSendURI, ipp.OpGetJobAttributes, ipp.OpCancelJob, ipp.OpCloseJob,
			ipp.OpHoldJob, ipp.OpReleaseJob, ipp.OpRestartJob, ipp.OpSetJobAttributes:
			jobID = ippRequestedJob(msg)
			switch {
			case !known(jobID):
				resp.Status = ipp.StatusNotFound
				message = fmt.Sprintf("Job #%d does not exist.", jobID)
			case msg.Operation == ipp.OpSendDocument || msg.Operation == ipp.OpSendURI || msg.Operation == ipp.OpCloseJob:
				extra = append(extra, ipp.Group{Tag: ipp.TagJob,
					Attrs: ipp.JobAttributes(s.persona, host, jobID, ipp.JobProcessing, "job-printing")})
			case msg.Operation == ipp.OpGetJobAttributes:
				extra = append(extra, ipp.Group{Tag: ipp.TagJob,
					Attrs: ipp.JobAttributes(s.persona, host, jobID, ipp.JobCompleted, "job-completed-successfully")})
			default:
				resp.Status = ipp.StatusNotPossible
				message = fmt.Sprintf("Job #%d is already completed - can't %s.", jobID, strings.ToLower(ipp.OperationName(msg.Operation)))
			}
		default:
			resp.Status = ipp.StatusOperationNotSupported
			message = "The operation " + ipp.OperationName(msg.Operation) + " is not supported."
		}
	}
	resp.Groups = append([]ipp.Group{ipp.OperationGroup(message)}, extra...)
	return ippReply{
		code:      http.StatusOK,
		ippStatus: ipp.StatusName(resp.Status),
		requestID: msg.RequestID,
		jobID:     jobID,
		data:      ipp.HTTPResponse(s.persona, http.StatusOK, "application/ipp", resp.Encode(), now, keepAlive),
	}
}

// decorateIPPFrame copies what the IPP request names into its read frame.
func decorateIPPFrame(frame *parsedIPP, msg ipp.Message) {
	frame.Command = ipp.OperationName(msg.Operation)
	frame.Version = msg.Version()
	frame.RequestID = msg.RequestID
	frame.JobID = ippRequestedJob(msg)
	frame.RequestingUser = msg.Get("operation", "requesting-user-name")
	frame.PrinterURI = msg.Get("operation", "printer-uri")
	frame.JobName = msg.Get("operation", "job-name")
	frame.DocumentFormat = msg.Get("operation", "document-format")
	frame.DocumentURI = msg.Get("operation", "document-uri")
	frame.DeviceURI = msg.Get("", "device-uri")
	frame.PPDName = msg.Get("", "ppd-name")
	frame.Attributes = msg.Attributes
	frame.Truncated = frame.Truncated || msg.Dropped
}

// HandleIPP takes a net.Conn and answers the Internet Printing Protocol over
// HTTP as a CUPS 2.4 server with one shared queue: printer and job queries
// are answered, print documents and PPDs are stored, admin operations ask for
// Basic credentials, and document-uri values are recorded but never fetched.
func HandleIPP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleIPP(ctx, newIPPServer(conn), md, logger, h)
}

func handleIPP(ctx context.Context, server *ippServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("ipp", conn, md, helpers.FirstOrEmpty[parsedIPP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ipp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close IPP connection", slog.String("protocol", "ipp"), producer.ErrAttr(err))
		}
	}()

	// readFailed maps a read error to the end reason; malformed input gets a
	// 400 like cupsd sends and is returned to the caller.
	readFailed := func(err error) error {
		if errors.Is(err, ipp.ErrMalformed) || errors.Is(err, ipp.ErrLineTooLong) || errors.Is(err, ipp.ErrBodyTooLarge) {
			logger.Debug("Malformed IPP request", slog.String("protocol", "ipp"), producer.ErrAttr(err))
			endReason = connection.EndReadError
			data := ipp.HTTPResponse(server.persona, http.StatusBadRequest, "", nil, server.now(), false)
			if werr := server.write(parsedIPP{Status: "400", Payload: data}); werr != nil {
				logger.Debug("Failed to write IPP error", slog.String("protocol", "ipp"), producer.ErrAttr(werr))
			}
			return err
		}
		logger.Debug("Failed to read data", slog.String("protocol", "ipp"), producer.ErrAttr(err))
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	writeFailed := func(err error) error {
		logger.Error("Failed to write IPP response", slog.String("protocol", "ipp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return err
	}

	for i := 0; i < ippMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "ipp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, raw, err := ipp.ReadHead(server.reader)
		if len(raw) > 0 && err != nil {
			server.events = append(server.events, parsedIPP{Direction: "read", Payload: raw})
		}
		if err != nil {
			return readFailed(err)
		}
		username, password, authed := req.BasicAuth()
		frame := parsedIPP{
			Direction: "read",
			Command:   req.Method,
			Method:    req.Method,
			Path:      req.Path,
			UserAgent: req.Header("User-Agent"),
			Username:  username,
			Password:  password,
			Payload:   raw,
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("IPP request received",
				slog.String("handler", "ipp"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("method", req.Method),
				slog.String("path", req.Path),
			)
		}

		if req.ExpectsContinue() {
			server.events = append(server.events, frame)
			if err := server.write(parsedIPP{Status: "100", Payload: ipp.Continue()}); err != nil {
				return writeFailed(err)
			}
			if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
				logger.Debug("Failed to set connection timeout", slog.String("protocol", "ipp"), producer.ErrAttr(err))
				endReason = connection.EndTimeout
				return nil
			}
			frame = parsedIPP{Direction: "read", Command: req.Method, Method: req.Method, Path: req.Path}
		}
		body, bodyRaw, truncated, err := ipp.ReadBody(server.reader, req, ippMaxBody)
		frame.Payload = append(frame.Payload, bodyRaw...)
		frame.Truncated = truncated
		if err != nil {
			if len(frame.Payload) > 0 {
				server.events = append(server.events, frame)
			}
			return readFailed(err)
		}

		now := server.now()
		keepAlive := req.KeepAlive()
		var reply ippReply
		switch {
		case req.Method == http.MethodPost && req.IsIPP():
			msg, perr := ipp.Parse(body)
			if len(body) >= 8 {
				decorateIPPFrame(&frame, msg)
			}
			if len(msg.Data) > 0 {
				if hash, err := storeIPP(msg.Data); err != nil {
					logger.Error("Failed to store IPP document", slog.String("protocol", "ipp"), producer.ErrAttr(err))
				} else {
					frame.PayloadHash = hash
				}
			}
			if perr != nil {
				logger.Debug("Malformed IPP message", slog.String("protocol", "ipp"), producer.ErrAttr(perr))
				reply = ippReply{code: http.StatusBadRequest, requestID: msg.RequestID,
					data: ipp.HTTPResponse(server.persona, http.StatusBadRequest, "", nil, now, keepAlive)}
			} else {
				reply = server.respondIPP(req, msg, authed)
			}
		case req.Method == http.MethodPut || strings.HasPrefix(req.Path, "/admin"):
			// configuration uploads and the admin pages need credentials
			if authed {
				reply.code = http.StatusForbidden
				reply.data = ipp.HTTPResponse(server.persona, reply.code, "", nil, now, keepAlive)
			} else {
				reply.code = http.StatusUnauthorized
				reply.data = ipp.Unauthorized(server.persona, now, keepAlive)
			}
		case req.Method == http.MethodGet || req.Method == http.MethodHead:
			code, data := ipp.WebPage(server.persona, req.Path, now, keepAlive)
			if req.Method == http.MethodHead {
				head, _, _ := strings.Cut(string(data), "\r\n\r\n")
				data = []byte(head + "\r\n\r\n")
			}
			reply = ippReply{code: code, data: data}
		case req.Method == http.MethodOptions:
			reply.code = http.StatusOK
			reply.data = ipp.HTTPResponse(server.persona, reply.code, "", nil, now, keepAlive,
				"Allow: GET, HEAD, OPTIONS, POST, PUT")
		default:
			reply.code = http.StatusBadRequest
			reply.data = ipp.HTTPResponse(server.persona, reply.code, "", nil, now, keepAlive)
		}
		server.events = append(server.events, frame)

		if err := server.write(parsedIPP{
			Status:    strconv.Itoa(reply.code),
			IPPStatus: reply.ippStatus,
			RequestID: reply.requestID,
			JobID:     reply.jobID,
			Payload:   reply.data,
		}); err != nil {
			return writeFailed(err)
		}
		if !keepAlive {
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
