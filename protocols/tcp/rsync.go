package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/rsync"
)

// rsyncMaxLine caps one client line (rsyncd's own line buffer is 1 KiB).
const rsyncMaxLine = 4096

type parsedRsync struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`  // version, list, module or auth on read frames
	Path      string `json:"path,omitempty"`     // module the client asked for
	Status    string `json:"status,omitempty"`   // reply name on write frames
	Version   string `json:"version,omitempty"`  // client protocol version, e.g. 31.0
	Digests   string `json:"digests,omitempty"`  // auth digests the client offers (protocol 30+)
	Username  string `json:"username,omitempty"` // user in the AUTHREQD reply
	Response  string `json:"response,omitempty"` // base64 digest of password + challenge
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// rsyncChallenge returns the AUTHREQD challenge; tests swap it.
var rsyncChallenge = func() (string, error) { return rsync.NewChallenge(rand.Reader) }

type rsyncStage int

const (
	rsyncStageVersion rsyncStage = iota
	rsyncStageModule
	rsyncStageAuth
)

// HandleRsync emulates an rsync daemon: version exchange, module list, and
// an auth challenge for every module that always fails. No transfer is
// emulated.
func HandleRsync(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var events []parsedRsync
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("rsync", conn, md, helpers.FirstOrEmpty[parsedRsync](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "rsync"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close rsync connection", slog.String("protocol", "rsync"), producer.ErrAttr(err))
		}
	}()

	write := func(status string, data []byte) error {
		if _, err := conn.Write(data); err != nil {
			return err
		}
		events = append(events, parsedRsync{Direction: "write", Status: status, Payload: data})
		return nil
	}

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "rsync"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}
	if err := write("greeting", []byte(rsync.Greeting)); err != nil {
		logger.Debug("Failed to write greeting", slog.String("protocol", "rsync"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	r := bufio.NewReaderSize(conn, rsyncMaxLine)
	stage := rsyncStageVersion
	var module string
	// every stage either advances or ends the session, so the loop is bounded
	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "rsync"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		line, err := r.ReadSlice('\n')
		truncated := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !truncated {
			logger.Debug("Failed to read data", slog.String("protocol", "rsync"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		line = append([]byte(nil), line...)
		frame := parsedRsync{Direction: "read", Payload: line, Truncated: truncated}
		if truncated {
			events = append(events, frame)
			endReason = connection.EndReadError
			return nil
		}

		var status string
		var reply []byte
		next := stage
		switch stage {
		case rsyncStageVersion:
			version, digests, ok := rsync.ParseGreeting(string(line))
			if !ok {
				status, reply = "protocol-error", []byte(rsync.ProtocolError)
				break
			}
			frame.Command, frame.Version, frame.Digests = "version", version, digests
			next = rsyncStageModule
		case rsyncStageModule:
			if rsync.IsListRequest(string(line)) {
				frame.Command = "list"
				status, reply = "list", rsync.ModuleList()
				break
			}
			module = rsync.ModuleName(string(line))
			frame.Command, frame.Path = "module", module
			if !rsync.HasModule(module) {
				status, reply = "unknown-module", rsync.UnknownModule(module)
				break
			}
			challenge, err := rsyncChallenge()
			if err != nil {
				events = append(events, frame)
				logger.Error("Failed to create auth challenge", slog.String("protocol", "rsync"), producer.ErrAttr(err))
				return err
			}
			status, reply = "authreqd", rsync.AuthRequired(challenge)
			next = rsyncStageAuth
		case rsyncStageAuth:
			frame.Command, frame.Path = "auth", module
			frame.Username, frame.Response = rsync.ParseAuth(string(line))
			status, reply = "auth-failed", rsync.AuthFailed(module)
		}
		events = append(events, frame)

		if reply != nil {
			if err := write(status, reply); err != nil {
				logger.Debug("Failed to write reply", slog.String("protocol", "rsync"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		}
		// the daemon hangs up after every reply except the auth challenge
		if next == stage {
			return nil
		}
		stage = next
	}
}
