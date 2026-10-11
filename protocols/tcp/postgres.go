package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/postgres"
)

// maxPostgresMessages bounds a session: SSL and GSS negotiation, the startup
// packet and the password message.
const maxPostgresMessages = 8

// postgresSalt returns the AuthenticationMD5Password salt; tests replace it.
var postgresSalt = func() [4]byte {
	var salt [4]byte
	_, _ = rand.Read(salt[:])
	return salt
}

type parsedPostgres struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Path      string `json:"path,omitempty"` // StartupMessage database
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// StartupMessage
	ProtocolVersion string            `json:"protocol_version,omitempty"`
	User            string            `json:"user,omitempty"`
	ApplicationName string            `json:"application_name,omitempty"`
	Params          map[string]string `json:"params,omitempty"` // the other startup parameters
	// PasswordMessage as sent (md5 hash string under md5 auth); it is a
	// guessing attempt and recorded in full
	Password string `json:"password,omitempty"`
	// ErrorResponse
	Message string `json:"message,omitempty"`
}

type postgresServer struct {
	events []parsedPostgres
	conn   net.Conn
	reader *bufio.Reader
	user   string
}

func (s *postgresServer) readStartup() (postgres.Startup, error) {
	st, err := postgres.ReadStartup(s.reader, postgres.MaxStartupLen)
	if len(st.Raw) > 0 {
		f := parsedPostgres{Direction: "read", Payload: st.Raw, Truncated: err != nil}
		if len(st.Raw) >= postgres.PeekLen {
			f.Command = st.Name()
		}
		s.events = append(s.events, f)
	}
	return st, err
}

func (s *postgresServer) readMessage() (postgres.Message, error) {
	msg, err := postgres.ReadMessage(s.reader, postgres.MaxStartupLen)
	if len(msg.Raw) > 0 {
		s.events = append(s.events, parsedPostgres{
			Direction: "read",
			Command:   postgres.MessageName(msg.Type),
			Payload:   msg.Raw,
			Truncated: err != nil,
		})
	}
	return msg, err
}

func (s *postgresServer) write(f parsedPostgres) error {
	if _, err := s.conn.Write(f.Payload); err != nil {
		return err
	}
	f.Direction = "write"
	s.events = append(s.events, f)
	return nil
}

func (s *postgresServer) writeError(e postgres.Error) error {
	return s.write(parsedPostgres{Command: "ErrorResponse", Status: e.Code, Message: e.Message, Payload: e.Build()})
}

func (s *postgresServer) lastRead() *parsedPostgres {
	return &s.events[len(s.events)-1]
}

// handleStartup records the StartupMessage and asks for an md5 password.
// done is true when the startup was rejected.
func (s *postgresServer) handleStartup(st postgres.Startup) (done bool, err error) {
	f := s.lastRead()
	major, minor := st.Version()
	f.ProtocolVersion = fmt.Sprintf("%d.%d", major, minor)
	if major != 3 {
		return true, s.writeError(postgres.UnsupportedProtocol(major, minor))
	}
	params, perr := postgres.ParseParams(st.Body())
	for _, p := range params {
		switch p.Name {
		case "user":
			f.User = p.Value
		case "database":
			f.Path = p.Value
		case "application_name":
			f.ApplicationName = p.Value
		default:
			if f.Params == nil {
				f.Params = map[string]string{}
			}
			f.Params[p.Name] = p.Value
		}
	}
	if perr != nil {
		// a real server logs the bad layout and hangs up without a reply
		return true, nil
	}
	if f.User == "" {
		return true, s.writeError(postgres.NoUser())
	}
	s.user = f.User
	if opts := postgres.UnsupportedOptions(params); minor > 0 || len(opts) > 0 {
		if err := s.write(parsedPostgres{
			Command: "NegotiateProtocolVersion",
			Payload: postgres.BuildNegotiateProtocolVersion(opts),
		}); err != nil {
			return true, err
		}
	}
	return false, s.write(parsedPostgres{
		Command: "AuthenticationMD5Password",
		Payload: postgres.BuildAuthMD5(postgresSalt()),
	})
}

// HandlePostgres answers the PostgreSQL protocol like a server with md5
// password authentication and no TLS: it declines SSL and GSS encryption,
// asks for a password after the StartupMessage and rejects it, recording
// the client's startup parameters.
func HandlePostgres(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &postgresServer{events: []parsedPostgres{}, conn: conn, reader: bufio.NewReader(conn)}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("postgres", conn, md, helpers.FirstOrEmpty[parsedPostgres](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "postgres"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close PostgreSQL connection", slog.String("protocol", "postgres"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sslDone, gssDone, started := false, false, false

	for i := 0; ; i++ {
		if i == maxPostgresMessages {
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "postgres"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		var done bool
		var err error
		if !started {
			st, rerr := server.readStartup()
			if rerr != nil {
				endReason = postgresReadEnd(rerr, logger)
				return nil
			}
			switch {
			case st.Code == postgres.SSLRequestCode && !sslDone:
				sslDone = true
				err = server.write(parsedPostgres{Command: "SSLResponse", Status: "N", Payload: postgres.NotSupported})
			case st.Code == postgres.GSSENCRequestCode && !gssDone:
				gssDone = true
				err = server.write(parsedPostgres{Command: "GSSENCResponse", Status: "N", Payload: postgres.NotSupported})
			case st.Code == postgres.CancelRequestCode:
				return nil
			default:
				// a repeated SSL or GSS request is an unsupported protocol
				// version, as on a real server
				done, err = server.handleStartup(st)
				started = true
				logger.Info(
					"PostgreSQL startup",
					slog.String("handler", "postgres"),
					slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
					slog.String("src_ip", host),
					slog.String("src_port", port),
					slog.String("user", server.user),
				)
			}
		} else {
			msg, rerr := server.readMessage()
			if rerr != nil {
				endReason = postgresReadEnd(rerr, logger)
				return nil
			}
			switch msg.Type {
			case 'p':
				server.lastRead().Password = msg.Password()
				err = server.writeError(postgres.PasswordFailed(server.user))
			case 'X':
				return nil
			default:
				err = server.writeError(postgres.ExpectedPassword(msg.Type))
			}
			done = true
		}
		if err != nil {
			logger.Error("Failed to write PostgreSQL response", slog.String("protocol", "postgres"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if done {
			return nil
		}
	}
}

// postgresReadEnd logs a failed read and returns the session end reason.
func postgresReadEnd(err error, logger interfaces.Logger) string {
	if errors.Is(err, postgres.ErrTooLong) || errors.Is(err, postgres.ErrMalformed) {
		logger.Debug("Invalid PostgreSQL message", slog.String("protocol", "postgres"), producer.ErrAttr(err))
		return connection.EndReadError
	}
	if !errors.Is(err, io.EOF) {
		logger.Debug("Failed to read PostgreSQL message", slog.String("protocol", "postgres"), producer.ErrAttr(err))
	}
	return connection.EndReasonFromRead(err)
}
