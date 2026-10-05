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
	"github.com/mushorg/glutton/protocols/tcp/mctp"
)

const (
	// mctpMaxBody caps the stored request body; real requests are a few hundred bytes.
	mctpMaxBody = 64 * 1024
	// mctpMaxRequests bounds the frames recorded for one connection.
	mctpMaxRequests = 100
)

type parsedMCTP struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"` // HI_SRDK_* function
	Method      string `json:"method,omitempty"`  // REMOTE
	CSeq        string `json:"cseq,omitempty"`
	FuncVersion string `json:"func_version,omitempty"`
	Segments    int    `json:"segments,omitempty"` // data segments in the request body
	Status      string `json:"status,omitempty"`   // response code on writes
	ReturnCode  string `json:"return_code,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

type mctpServer struct {
	events []parsedMCTP
	conn   net.Conn
	reader *bufio.Reader
}

func (s *mctpServer) read() (mctp.Request, error) {
	req, raw, truncated, err := mctp.ReadRequest(s.reader, mctpMaxBody)
	if len(raw) == 0 {
		return req, err
	}
	s.events = append(s.events, parsedMCTP{
		Direction:   "read",
		Command:     req.Function,
		Method:      req.Method,
		CSeq:        req.Header("CSeq"),
		FuncVersion: req.Header("Func-Version"),
		Segments:    len(req.Segments),
		Payload:     raw,
		Truncated:   truncated,
	})
	return req, err
}

func (s *mctpServer) write(cseq string, returnCode int) error {
	data := mctp.BuildResponse(cseq, returnCode)
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedMCTP{
		Direction:  "write",
		CSeq:       cseq,
		Status:     "200",
		ReturnCode: strconv.Itoa(returnCode),
		Payload:    data,
	})
	return nil
}

// HandleMCTP takes a net.Conn and answers MCTP/1.0, the HiSilicon DVR control
// protocol on tcp/9000 (HI_SRDK_* calls). Every call gets an empty success reply.
func HandleMCTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mctpServer{events: []parsedMCTP{}, conn: conn, reader: bufio.NewReader(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("mctp", conn, md, helpers.FirstOrEmpty[parsedMCTP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mctp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MCTP connection", slog.String("protocol", "mctp"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < mctpMaxRequests; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "mctp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		req, err := server.read()
		if err != nil {
			if errors.Is(err, mctp.ErrMalformed) || errors.Is(err, mctp.ErrLineTooLong) || errors.Is(err, mctp.ErrBodyTooLarge) {
				logger.Debug("Malformed MCTP request", slog.String("protocol", "mctp"), producer.ErrAttr(err))
				endReason = connection.EndReadError
				return err
			}
			logger.Debug("Failed to read data", slog.String("protocol", "mctp"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("MCTP request received",
				slog.String("handler", "mctp"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("function", req.Function),
			)
		}
		if err := server.write(req.Header("CSeq"), 0); err != nil {
			logger.Error("Failed to write MCTP response", slog.String("protocol", "mctp"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
