package tcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/mssql"
	"github.com/mushorg/glutton/protocols/tcp/rdp"
	"github.com/spf13/viper"
)

const (
	// maxMSSQLMessages bounds a session up to login: PRELOGIN, LOGIN7 and one
	// SSPI round trip end in a login failure well before it.
	maxMSSQLMessages = 8
	// maxMSSQLMessageLen caps one reassembled message before login; a LOGIN7
	// is a few hundred bytes. It also caps the payload recorded for a frame.
	maxMSSQLMessageLen = 64 * 1024
	// maxMSSQLRequests bounds the SQL batches and RPCs after an accepted login.
	maxMSSQLRequests = 64
	// maxMSSQLRequestLen caps one message after login: a CLR assembly or
	// dropper sent as a hex literal runs to hundreds of KiB.
	maxMSSQLRequestLen = 1 << 20
	// maxMSSQLQuery caps the recorded query text; longer ones are stored whole
	// with helpers.Store.
	maxMSSQLQuery = 4096
	// mssqlAcceptAfter is how many SQL-auth logins from one source (counted
	// across its connections within a recall visit) fail before the next one
	// is accepted; mssql.accept_after overrides it.
	mssqlAcceptAfter = 3
)

// mssqlNow and mssqlServerChallenge are vars so tests get a fixed CHALLENGE.
var (
	mssqlNow             = time.Now
	mssqlServerChallenge = func() ([]byte, error) {
		b := make([]byte, 8)
		_, err := rand.Read(b)
		return b, err
	}
	// mssqlStore keeps long or binary query texts; tests replace it.
	mssqlStore = helpers.Store
)

// mssqlRecall counts each source's failed logins; tests swap it for a store
// they control.
var mssqlRecall = recall.Shared

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
	// SQL_BATCH / RPC after login
	Query       string `json:"query,omitempty"`        // query text, or the sp_executesql statement
	PayloadHash string `json:"payload_hash,omitempty"` // SHA-256 of the stored query text, when long or carrying a binary
	// write
	ErrorNumber uint32 `json:"error_number,omitempty"`
	Visit       int    `json:"visit,omitempty"` // source's visit number, on login replies
}

type mssqlServer struct {
	events []parsedMSSQL
	conn   net.Conn
	logger interfaces.Logger
	ip     net.IP
	visit  int
	// legacy is set by a pre-TDS 7.2 LOGIN7 and sizes the ERROR/DONE fields
	legacy bool
	// tdsVersion is the LOGIN7 TDSVersion
	tdsVersion uint32
	// challenged is set once an NTLM CHALLENGE was sent
	challenged bool
	// loggedIn is set once a LOGIN7 was accepted
	loggedIn bool
}

func (s *mssqlServer) read() (mssql.Message, error) {
	maxLen := maxMSSQLMessageLen
	if s.loggedIn {
		maxLen = maxMSSQLRequestLen
	}
	msg, err := mssql.ReadMessage(s.conn, maxLen)
	if len(msg.Raw) > 0 {
		payload, capped := msg.Raw, false
		if len(payload) > maxMSSQLMessageLen {
			payload, capped = payload[:maxMSSQLMessageLen], true
		}
		s.events = append(s.events, parsedMSSQL{
			Direction: "read",
			Command:   mssql.TypeName(msg.Type),
			Payload:   payload,
			Truncated: msg.Truncated || capped || err != nil,
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
	if err := s.write(mssql.BuildLoginError(e), "login-failed", e.Number); err != nil {
		return err
	}
	s.events[len(s.events)-1].Visit = s.visit
	return nil
}

// acceptLogin reports whether this SQL-auth login is accepted: the source has
// already failed mssql.accept_after of them within its recall visit. With
// recall disabled only this connection's attempt counts.
func (s *mssqlServer) acceptLogin() bool {
	if viper.IsSet("mssql.accept_logins") && !viper.GetBool("mssql.accept_logins") {
		return false
	}
	after := mssqlAcceptAfter
	if viper.IsSet("mssql.accept_after") {
		after = viper.GetInt("mssql.accept_after")
	}
	tries := mssqlRecall.Count("mssql", s.ip, "login")
	if tries == 0 {
		tries = 1
	}
	return tries > after
}

// loginAck accepts login and switches the session to answering requests.
func (s *mssqlServer) loginAck(login mssql.Login7, computer string) error {
	resp := mssql.BuildLoginAck(mssql.LoginAckOptions{
		TDSVersion: login.TDSVersion,
		PacketSize: login.PacketSize,
		Database:   login.Database,
		Language:   login.Language,
		Server:     computer,
	})
	if err := s.write(resp, "login-ok", 0); err != nil {
		return err
	}
	s.events[len(s.events)-1].Visit = s.visit
	s.loggedIn = true
	return nil
}

// recordQuery sets the query text on frame f, capped at maxMSSQLQuery; a long
// query or one carrying an executable is stored whole.
func (s *mssqlServer) recordQuery(f *parsedMSSQL, query string) {
	if query == "" {
		return
	}
	if len(query) > maxMSSQLQuery || mssql.LooksLikeBinaryBlob(query) {
		hash, err := mssqlStore([]byte(query), filepath.Join("payloads", "mssql"))
		if err != nil {
			s.logger.Error("Failed to store MSSQL query", slog.String("protocol", "mssql"), producer.ErrAttr(err))
		}
		f.PayloadHash = hash
	}
	if len(query) > maxMSSQLQuery {
		n := maxMSSQLQuery
		for n > 0 && !utf8.RuneStart(query[n]) {
			n--
		}
		query, f.Truncated = query[:n], true
	}
	f.Query = query
}

// handleRequest records and answers a request after login. Nothing in it is
// executed.
func (s *mssqlServer) handleRequest(msg mssql.Message) error {
	computer, _ := rdp.Identity()
	opts := mssql.QueryOptions{TDSVersion: s.tdsVersion, Server: computer}
	f := s.lastRead()
	switch msg.Type {
	case mssql.TypeSQLBatch:
		query := mssql.ParseSQLBatch(msg.Data)
		s.recordQuery(f, query)
		resp, status := mssql.BuildBatchReply(query, opts)
		return s.write(resp, status, 0)
	case mssql.TypeRPC:
		call := mssql.ParseRPC(msg.Data)
		if call.Proc != "" {
			f.Command = call.Proc
		}
		s.recordQuery(f, call.Statement)
		resp, status := mssql.BuildRPCReply(call.Statement, opts)
		return s.write(resp, status, 0)
	case mssql.TypeAttention:
		return s.write(mssql.BuildAttentionAck(s.tdsVersion), "attention", 0)
	default:
		return s.write(mssql.BuildDone(s.tdsVersion), mssql.StatusDone, 0)
	}
}

// noteVisit records what the source did in its recall visit.
func (s *mssqlServer) noteVisit() {
	mssqlRecall.Note("mssql", s.ip, func(sum *recall.Summary) {
		for _, f := range s.events {
			if f.Direction != "read" {
				continue
			}
			sum.AddCommand(f.Command)
			sum.AddUsername(f.Username)
		}
	})
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
	s.tdsVersion = login.TDSVersion
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
		if s.acceptLogin() {
			return false, s.loginAck(login, computer)
		}
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

// isMSSQLRequest reports whether a message type is sent after login.
func isMSSQLRequest(t byte) bool {
	switch t {
	case mssql.TypeSQLBatch, mssql.TypeRPC, mssql.TypeAttention, mssql.TypeTransaction:
		return true
	}
	return false
}

// HandleMSSQL answers TDS PRELOGIN and LOGIN7 like a SQL Server, recording the
// client and login fields. SQL-auth logins fail until the source has made
// mssql.accept_after of them; the next one is accepted and the session's SQL
// batches and RPCs get canned replies.
func HandleMSSQL(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mssqlServer{events: []parsedMSSQL{}, conn: conn, logger: logger}
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	server.ip = net.ParseIP(host)
	server.visit = mssqlRecall.Begin("mssql", server.ip, 0).Number
	endReason := connection.EndHandlerClose
	defer func() {
		server.noteVisit()
		md.EndReason = endReason
		if err := h.ProduceTCP("mssql", conn, md, helpers.FirstOrEmpty[parsedMSSQL](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mssql"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MSSQL connection", slog.String("protocol", "mssql"), producer.ErrAttr(err))
		}
	}()

	limit := maxMSSQLMessages
	for i := 0; ; i++ {
		if i == limit {
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

		if isMSSQLRequest(msg.Type) != server.loggedIn {
			// SQL Server drops a client that sends a request before login, or
			// a login message after it
			logger.Debug("Unexpected TDS message", slog.String("protocol", "mssql"), slog.String("command", mssql.TypeName(msg.Type)), slog.Bool("logged_in", server.loggedIn))
			return nil
		}

		var done bool
		switch msg.Type {
		case mssql.TypeSQLBatch, mssql.TypeRPC, mssql.TypeAttention, mssql.TypeTransaction:
			err = server.handleRequest(msg)
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
			if server.loggedIn {
				limit = i + 1 + maxMSSQLRequests
			}
		case mssql.TypeSSPI:
			done, err = true, server.handleSSPI(msg.Data)
		default:
			logger.Debug("Unexpected TDS message", slog.String("protocol", "mssql"), slog.String("command", mssql.TypeName(msg.Type)))
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
