package tcp

// The SMB emulation (session state, SMB1/SMB2 dispatch, transactions,
// DoublePulsar, file and pipe handles) lives in protocols/tcp/smb as
// smb.Server. This file owns the connection lifecycle: timeouts, the frame
// bound, producing the single event, and closing.

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

const maxSMBMessages = 128

// parsedSMB is one frame of the session; see smb.Event.
type parsedSMB = smb.Event

// Seams for tests: artifact storage, randomness (NTLM challenge, DoublePulsar
// signature), the visit memory (swapped for a store with a fake clock), and the
// per-file upload cap.
var (
	smbStore         = helpers.Store
	smbReadRand      = rand.Read
	smbRecall        = recall.Shared
	maxSMBFileBuffer = smb.DefaultMaxFileBuffer
)

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := smb.NewServer(smb.Config{
		Conn:          conn,
		Logger:        logger,
		SrcIP:         remoteIP(conn),
		Store:         smbStore,
		ReadRand:      smbReadRand,
		Recall:        smbRecall,
		MaxFileBuffer: maxSMBFileBuffer,
	})
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		server.Finish()
		events := server.Events()
		if err := h.ProduceTCP("smb", conn, md, helpers.FirstOrEmpty[parsedSMB](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "smb"), producer.ErrAttr(err))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SMB connection", producer.ErrAttr(err), slog.String("protocol", "smb"))
		}
	}()

	for i := 0; i < maxSMBMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		frame, err := server.ReadFrame()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if err := server.HandleFrame(frame); err != nil {
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
