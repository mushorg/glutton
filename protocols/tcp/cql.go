package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/cql"
)

const (
	// cqlMaxFrames bounds the frames read on one connection.
	cqlMaxFrames = 32
	// cqlMaxDrain bounds the bytes captured after a non-CQL first byte.
	cqlMaxDrain = 4096

	// Persona: a stock Cassandra 3.11 node (the release the Thrift handler on
	// tcp/9160 also impersonates; Thrift was removed in 4.0) configured with
	// PasswordAuthenticator so clients send credentials.
	cqlVersion          = "3.4.4"
	cqlAuthenticator    = "org.apache.cassandra.auth.PasswordAuthenticator"
	cqlSupportedVersion = "3/v3, 4/v4, 5/v5-beta"
	cqlBootstrapping    = "Cannot read from a bootstrapping node"
)

// cqlSupported is the SUPPORTED body of Cassandra 3.11's OptionsMessage, in
// the iteration order of the Java HashMap it is built from.
var cqlSupported = cql.StringMultimap([]cql.MultimapEntry{
	{Key: "COMPRESSION", Values: []string{"snappy", "lz4"}},
	{Key: "CQL_VERSION", Values: []string{cqlVersion}},
})

// cqlDrainTimeout bounds how long the handler waits for the rest of a
// non-CQL probe before replying. Tests shorten it.
var cqlDrainTimeout = 250 * time.Millisecond

type parsedCQL struct {
	Direction string            `json:"direction,omitempty"`
	Header    *cql.Header       `json:"header,omitempty"`  // read: parsed frame header
	Command   string            `json:"command,omitempty"` // opcode name
	Options   map[string]string `json:"options,omitempty"` // read: STARTUP options
	Query     string            `json:"query,omitempty"`   // read: QUERY/PREPARE CQL text
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	Status    string            `json:"status,omitempty"` // write: reply outcome
	Payload   []byte            `json:"payload,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
}

type cqlState int

const (
	cqlUninitialized cqlState = iota
	cqlAuthenticating
	cqlEstablished
)

type cqlServer struct {
	events []parsedCQL
	conn   net.Conn
	state  cqlState
}

func (s *cqlServer) write(command, status string, data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedCQL{Direction: "write", Command: command, Status: status, Payload: data})
	return nil
}

func (s *cqlServer) writeError(version uint8, stream int16, code uint32, status, msg string) error {
	return s.write("ERROR", status, cql.BuildFrame(version, stream, cql.OpError, cql.ErrorBody(code, msg)))
}

func cqlUnsupportedVersion(v uint8) string {
	return fmt.Sprintf("Invalid or unsupported protocol version (%d); supported versions are (%s)", v, cqlSupportedVersion)
}

// annotate copies the parsed request fields into the read frame. Compressed
// bodies are left undecoded.
func (s *cqlServer) annotate(frame *parsedCQL, hdr *cql.Header, body []byte) {
	if hdr.Flags&cql.FlagCompression != 0 {
		return
	}
	switch hdr.Opcode {
	case cql.OpStartup:
		frame.Options, _ = cql.ParseStringMap(body)
	case cql.OpQuery, cql.OpPrepare:
		frame.Query, _ = cql.ParseLongString(body)
	case cql.OpAuthResponse:
		if token, err := cql.ParseBytes(body); err == nil {
			frame.Username, frame.Password, _ = cql.ParsePlainSASL(token)
		}
	}
}

// respond answers one request. It returns false when the connection should
// be closed after the reply.
func (s *cqlServer) respond(hdr *cql.Header, frame *parsedCQL) (bool, error) {
	v, stream, op := hdr.Version, hdr.Stream, hdr.Opcode
	name := cql.OpcodeName(op)

	switch {
	case hdr.Response:
		return false, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
			fmt.Sprintf("Wrong protocol direction (expected REQUEST, got RESPONSE) for opcode %d (%s)", op, name))
	case v < 3:
		return false, s.writeError(v, stream, cql.ErrProtocol, "protocol_error", cqlUnsupportedVersion(v))
	case v == 5 && hdr.Flags&cql.FlagUseBeta == 0:
		return false, s.writeError(4, stream, cql.ErrProtocol, "protocol_error",
			"Beta version of the protocol used (5/v5-beta), but USE_BETA flag is unset")
	}

	if op == cql.OpOptions {
		return true, s.write("SUPPORTED", "supported", cql.BuildFrame(v, stream, cql.OpSupported, cqlSupported))
	}

	switch s.state {
	case cqlUninitialized:
		if op != cql.OpStartup {
			return true, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
				fmt.Sprintf("Unexpected message %s, expecting STARTUP or OPTIONS", name))
		}
		if _, ok := frame.Options["CQL_VERSION"]; !ok && hdr.Flags&cql.FlagCompression == 0 {
			return true, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
				"Missing value CQL_VERSION in STARTUP message")
		}
		s.state = cqlAuthenticating
		return true, s.write("AUTHENTICATE", "authenticate", cql.BuildFrame(v, stream, cql.OpAuthenticate, cql.StringBody(cqlAuthenticator)))
	case cqlAuthenticating:
		if op != cql.OpAuthResponse {
			return true, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
				fmt.Sprintf("Unexpected message %s, expecting SASL_RESPONSE", name))
		}
		// Every credential is accepted so the session continues to queries.
		s.state = cqlEstablished
		return true, s.write("AUTH_SUCCESS", "auth_success", cql.BuildFrame(v, stream, cql.OpAuthSuccess, cql.NullBytes()))
	}

	switch op {
	case cql.OpStartup:
		return true, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
			"Unexpected message STARTUP, the connection is already initialized")
	case cql.OpRegister:
		return true, s.write("READY", "ready", cql.BuildFrame(v, stream, cql.OpReady, nil))
	case cql.OpQuery, cql.OpPrepare, cql.OpExecute, cql.OpBatch:
		return true, s.writeError(v, stream, cql.ErrIsBootstrapping, "is_bootstrapping", cqlBootstrapping)
	case cql.OpAuthResponse:
		return true, s.writeError(v, stream, cql.ErrProtocol, "protocol_error",
			fmt.Sprintf("Unexpected message %s", name))
	}
	return false, s.writeError(v, stream, cql.ErrProtocol, "protocol_error", fmt.Sprintf("Unknown opcode %d", op))
}

// HandleCQL takes a net.Conn and answers the Cassandra native protocol
// (CQL binary protocol v3-v5) on tcp/9042 as a stock Cassandra 3.11 node with
// PasswordAuthenticator: OPTIONS gets SUPPORTED, STARTUP gets AUTHENTICATE,
// any AUTH_RESPONSE succeeds, REGISTER gets READY and queries fail with
// Is_bootstrapping.
func HandleCQL(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &cqlServer{events: []parsedCQL{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("cql", conn, md, helpers.FirstOrEmpty[parsedCQL](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "cql"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close CQL connection", slog.String("protocol", "cql"), producer.ErrAttr(err))
		}
	}()

	for i := 0; i < cqlMaxFrames; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "cql"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		raw, hdr, err := cql.ReadFrame(conn)
		if len(raw) > 0 {
			server.events = append(server.events, parsedCQL{Direction: "read", Header: hdr, Payload: raw})
		}
		if hdr != nil {
			server.events[len(server.events)-1].Command = cql.OpcodeName(hdr.Opcode)
		}
		switch {
		case errors.Is(err, cql.ErrUnknownVersion):
			// Non-CQL traffic: capture what the client already sent, then
			// reject it the way Cassandra does and close.
			frame := &server.events[len(server.events)-1]
			frame.Payload = append(frame.Payload, cqlDrain(conn)...)
			logger.Debug("Unknown CQL protocol version", slog.String("protocol", "cql"), producer.ErrAttr(err))
			if err := server.writeError(4, 0, cql.ErrProtocol, "protocol_error", cqlUnsupportedVersion(raw[0]&0x7f)); err != nil {
				endReason = connection.EndWriteError
			}
			return nil
		case errors.Is(err, cql.ErrBodyTooLarge):
			server.events[len(server.events)-1].Truncated = true
			logger.Debug("CQL frame too large", slog.String("protocol", "cql"), producer.ErrAttr(err))
			endReason = connection.EndReadError
			return nil
		case err != nil:
			logger.Debug("Failed to read data", slog.String("protocol", "cql"), producer.ErrAttr(err))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}

		frame := &server.events[len(server.events)-1]
		server.annotate(frame, hdr, raw[cql.HeaderSize(hdr.Version):])

		if i == 0 {
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			logger.Info("CQL request received",
				slog.String("handler", "cql"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("command", frame.Command),
			)
		}

		keep, err := server.respond(hdr, frame)
		if err != nil {
			logger.Debug("Failed to write CQL reply", slog.String("protocol", "cql"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return nil
		}
		if !keep {
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}

// cqlDrain reads whatever else the client sent within cqlDrainTimeout.
func cqlDrain(conn net.Conn) []byte {
	if err := conn.SetReadDeadline(time.Now().Add(cqlDrainTimeout)); err != nil {
		return nil
	}
	buf := make([]byte, cqlMaxDrain)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	return buf[:n]
}
