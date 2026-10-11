package tcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/mssql"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
)

const (
	// maxMSSQLMessages bounds a session: PRELOGIN, LOGIN7 and one SSPI round
	// trip end in a login failure well before it.
	maxMSSQLMessages = 8
	// maxMSSQLMessageLen caps one reassembled message; a LOGIN7 is a few
	// hundred bytes.
	maxMSSQLMessageLen = 64 * 1024
)

// mssqlNow and mssqlServerChallenge are vars so tests get a fixed CHALLENGE.
var (
	mssqlNow             = time.Now
	mssqlServerChallenge = func() ([]byte, error) {
		b := make([]byte, 8)
		_, err := rand.Read(b)
		return b, err
	}
)

type parsedMSSQL struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Status    string `json:"status,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// PRELOGIN
	ClientVersion string `json:"client_version,omitempty"`
	Encryption    string `json:"encryption,omitempty"`
	Instance      string `json:"instance,omitempty"`
	ThreadID      uint32 `json:"thread_id,omitempty"`
	// LOGIN7; the password is a guessing attempt and recorded as sent
	TDSVersion      string `json:"tds_version,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	AppName         string `json:"app_name,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	ClientInterface string `json:"client_interface,omitempty"`
	Database        string `json:"database,omitempty"`
	Language        string `json:"language,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	IntegratedAuth  bool   `json:"integrated_auth,omitempty"`
	// NTLM from the SSPI blob
	NTLMType        int    `json:"ntlm_type,omitempty"`
	NTLMDomain      string `json:"ntlm_domain,omitempty"`
	NTLMUser        string `json:"ntlm_user,omitempty"`
	NTLMWorkstation string `json:"ntlm_workstation,omitempty"`
	NTLMVersion     string `json:"ntlm_version,omitempty"`
	// write
	ErrorNumber uint32 `json:"error_number,omitempty"`
}

type mssqlServer struct {
	events []parsedMSSQL
	conn   net.Conn
	// legacy is set by a pre-TDS 7.2 LOGIN7 and sizes the ERROR/DONE fields
	legacy bool
	// challenged is set once an NTLM CHALLENGE was sent
	challenged bool
}

func (s *mssqlServer) read() (mssql.Message, error) {
	msg, err := mssql.ReadMessage(s.conn, maxMSSQLMessageLen)
	if len(msg.Raw) > 0 {
		s.events = append(s.events, parsedMSSQL{
			Direction: "read",
			Command:   mssql.TypeName(msg.Type),
			Payload:   msg.Raw,
			Truncated: msg.Truncated || err != nil,
		})
	}
	return msg, err
}

func (s *mssqlServer) write(data []byte, status string, errNumber uint32) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedMSSQL{
		Direction:   "write",
		Status:      status,
		Payload:     data,
		ErrorNumber: errNumber,
	})
	return nil
}

func (s *mssqlServer) lastRead() *parsedMSSQL {
	return &s.events[len(s.events)-1]
}

// recordNTLM sets the NTLM message type and, for an AUTHENTICATE, the
// non-secret identity on the last read frame.
func (s *mssqlServer) recordNTLM(msg []byte) {
	f := s.lastRead()
	f.NTLMType = int(ntlm.MessageType(msg))
	if f.NTLMType != ntlm.MsgAuthenticate {
		return
	}
	auth := ntlm.ParseAuthenticate(msg)
	f.NTLMDomain = auth.Domain
	f.NTLMUser = auth.User
	f.NTLMWorkstation = auth.Workstation
	f.NTLMVersion = auth.Version
}

func (s *mssqlServer) loginError(e mssql.LoginError) error {
	return s.write(mssql.BuildLoginError(e), "login-failed", e.Number)
}

// challenge answers an NTLM NEGOTIATE in blob with an SSPI CHALLENGE.
func (s *mssqlServer) challenge(blob, negotiate []byte) error {
	serverChallenge, err := mssqlServerChallenge()
	if err != nil {
		return err
	}
	computer, domain := rdp.Identity()
	var clientFlags uint32
	if len(negotiate) >= 16 {
		clientFlags = binary.LittleEndian.Uint32(negotiate[12:16])
	}
	resp := mssql.BuildSSPIChallenge(blob, mssql.ChallengeOptions{
		ServerChallenge: serverChallenge,
		Computer:        computer,
		Domain:          domain,
		ClientFlags:     clientFlags,
		Now:             mssqlNow(),
	})
	if resp == nil {
		return errors.New("failed to build NTLM challenge")
	}
	s.challenged = true
	return s.write(resp, "sspi-challenge", 0)
}

// handleLogin7 records the LOGIN7 fields and answers it. done is true when
// the login was rejected and the session is over; err is a write error.
func (s *mssqlServer) handleLogin7(login mssql.Login7) (done bool, err error) {
	s.legacy = mssql.LegacyTDS(login.TDSVersion)
	f := s.lastRead()
	f.TDSVersion = mssql.TDSVersionString(login.TDSVersion)
	f.Username = login.UserName
	f.Password = login.Password
	f.Hostname = login.HostName
	f.AppName = login.AppName
	f.ServerName = login.ServerName
	f.ClientInterface = login.ClientInterface
	f.Database = login.Database
	f.Language = login.Language
	f.ClientID = login.ClientID
	f.IntegratedAuth = login.IntegratedAuth

	computer, _ := rdp.Identity()
	if !login.IntegratedAuth {
		return true, s.loginError(mssql.LoginFailed(login.UserName, computer, s.legacy))
	}
	if msg, ok := ntlm.Find(login.SSPI); ok {
		s.recordNTLM(msg)
		if ntlm.MessageType(msg) == ntlm.MsgNegotiate {
			return false, s.challenge(login.SSPI, msg)
		}
	}
	// Kerberos, or an NTLM message out of order
	return true, s.loginError(mssql.UntrustedDomain(computer, s.legacy))
}

// handleSSPI answers the client's NTLM AUTHENTICATE with a login failure.
func (s *mssqlServer) handleSSPI(data []byte) error {
	computer, _ := rdp.Identity()
	msg, ok := ntlm.Find(data)
	if !ok || !s.challenged {
		return s.loginError(mssql.UntrustedDomain(computer, s.legacy))
	}
	s.recordNTLM(msg)
	auth := ntlm.ParseIdentity(msg)
	if ntlm.MessageType(msg) != ntlm.MsgAuthenticate || auth.User == "" {
		return s.loginError(mssql.UntrustedDomain(computer, s.legacy))
	}
	user := auth.User
	if auth.Domain != "" {
		user = auth.Domain + `\` + user
	}
	return s.loginError(mssql.LoginFailed(user, computer, s.legacy))
}

// HandleMSSQL answers TDS PRELOGIN and LOGIN7 like a SQL Server that rejects
// every login, recording the client and login fields.
func HandleMSSQL(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mssqlServer{events: []parsedMSSQL{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("mssql", conn, md, helpers.FirstOrEmpty[parsedMSSQL](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mssql"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MSSQL connection", slog.String("protocol", "mssql"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; ; i++ {
		if i == maxMSSQLMessages {
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "mssql"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		msg, err := server.read()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Debug("Failed to read TDS message", slog.String("protocol", "mssql"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			if errors.Is(err, mssql.ErrBadHeader) {
				endReason = connection.EndReadError
			}
			return nil
		}
		if msg.Truncated {
			logger.Debug("TDS message exceeds cap", slog.String("protocol", "mssql"), slog.Int("bytes", len(msg.Raw)))
			endReason = connection.EndMaxFrames
			return nil
		}

		var done bool
		switch msg.Type {
		case mssql.TypePrelogin:
			pre, perr := mssql.ParsePrelogin(msg.Data)
			f := server.lastRead()
			f.ClientVersion = pre.Version
			f.Encryption = pre.Encryption
			f.Instance = pre.Instance
			f.ThreadID = pre.ThreadID
			if perr != nil {
				logger.Debug("Malformed PRELOGIN", slog.String("protocol", "mssql"), producer.ErrAttr(perr))
				return nil
			}
			err = server.write(mssql.BuildPreloginResponse(), "prelogin", 0)
		case mssql.TypeLogin7:
			login, perr := mssql.ParseLogin7(msg.Data)
			if perr != nil {
				logger.Debug("Malformed LOGIN7", slog.String("protocol", "mssql"), producer.ErrAttr(perr))
				return nil
			}
			logger.Info(
				"MSSQL login attempt",
				slog.String("handler", "mssql"),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("username", login.UserName),
				slog.String("app_name", login.AppName),
			)
			done, err = server.handleLogin7(login)
		case mssql.TypeSSPI:
			done, err = true, server.handleSSPI(msg.Data)
		default:
			// SQL Server drops a client that sends anything else before login
			logger.Debug("Unexpected TDS message before login", slog.String("protocol", "mssql"), slog.String("command", mssql.TypeName(msg.Type)))
			return nil
		}
		if err != nil {
			logger.Error("Failed to write TDS response", slog.String("protocol", "mssql"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if done {
			return nil
		}
	}
}
