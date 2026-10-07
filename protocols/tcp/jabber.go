package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/jabber"
)

const (
	jabberMaxFrames    = 32
	jabberMaxFrameSize = 4096
	// jabberDefaultHost is the stream "from" when the client omits "to".
	jabberDefaultHost = "localhost"
)

var (
	errJabberFrameTooLarge = errors.New("jabber: frame exceeds capture cap")
)

type parsedJabber struct {
	Direction  string `json:"direction,omitempty"`
	Command    string `json:"command,omitempty"`
	Path       string `json:"path,omitempty"`
	Status     string `json:"status,omitempty"`
	Mechanism  string `json:"mechanism,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	TLS        bool   `json:"tls,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type jabberServer struct {
	events []parsedJabber
	conn   net.Conn
	// r and w are the current transport: the raw conn, or a *tls.Conn after
	// direct TLS or STARTTLS.
	r     *bufio.Reader
	w     io.Writer
	buf   []byte
	chunk []byte
	tls   bool
	// newStreamID generates the server stream id; tests replace it.
	newStreamID func() string
}

func newJabberServer(conn net.Conn) *jabberServer {
	return &jabberServer{
		events:      []parsedJabber{},
		conn:        conn,
		r:           bufio.NewReaderSize(conn, jabberMaxFrameSize),
		w:           conn,
		chunk:       make([]byte, jabberMaxFrameSize),
		newStreamID: randomStreamID,
	}
}

func randomStreamID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *jabberServer) recordPartial(data []byte) {
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}
	s.events = append(s.events, parsedJabber{
		Direction: "read",
		TLS:       s.tls,
		Payload:   bytes.Clone(data),
		Truncated: len(data) >= jabberMaxFrameSize,
	})
}

// read returns the next complete stream header or stanza and records it as a
// read frame. The buffer never grows past jabberMaxFrameSize.
func (s *jabberServer) read() (jabber.Stanza, error) {
	for {
		frame, rest, ok, err := jabber.NextFrame(s.buf)
		if err != nil {
			s.recordPartial(s.buf)
			s.buf = nil
			return jabber.Stanza{}, err
		}
		if ok {
			payload := bytes.Clone(frame)
			s.buf = rest
			st, _ := jabber.ParseStanza(payload)
			ev := parsedJabber{
				Direction: "read",
				Command:   st.Name,
				Path:      st.To,
				Mechanism: st.Mechanism,
				TLS:       s.tls,
				Payload:   payload,
			}
			switch {
			case st.Name == "auth" && st.Mechanism == "PLAIN":
				if _, user, pass, err := jabber.DecodePlain(st.Text); err == nil {
					ev.Username, ev.Password = user, pass
				}
			case st.Name == "iq" && st.QueryNS == jabber.NSIQAuth:
				ev.Username, ev.Password = st.Username, st.Password
			}
			s.events = append(s.events, ev)
			return st, nil
		}
		if len(s.buf) >= jabberMaxFrameSize {
			s.recordPartial(s.buf)
			s.buf = nil
			return jabber.Stanza{}, errJabberFrameTooLarge
		}
		n, err := s.r.Read(s.chunk[:jabberMaxFrameSize-len(s.buf)])
		if n > 0 {
			s.buf = append(s.buf, s.chunk[:n]...)
		}
		if err != nil {
			s.recordPartial(s.buf)
			s.buf = nil
			return jabber.Stanza{}, err
		}
	}
}

func (s *jabberServer) write(command, path, status string, data []byte) error {
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedJabber{
		Direction: "write",
		Command:   command,
		Path:      path,
		Status:    status,
		TLS:       s.tls,
		Payload:   data,
	})
	return nil
}

// startTLS runs a server TLS handshake over the current reader and switches
// the transport to it. The client's handshake bytes are recorded as a frame.
func (s *jabberServer) startTLS() error {
	tlsConn, info, err := helpers.TerminateTLSFrom(s.conn, s.r)
	s.tls = true
	s.events = append(s.events, parsedJabber{
		Direction:  "read",
		Command:    "tls",
		TLS:        true,
		ServerName: info.ServerName,
		Payload:    info.Hello,
		Truncated:  info.Truncated,
	})
	if err != nil {
		return err
	}
	s.r = bufio.NewReaderSize(tlsConn, jabberMaxFrameSize)
	s.w = tlsConn
	s.buf = nil
	return nil
}

// HandleJabber emulates an XMPP (RFC 6120) server up to SASL authentication.
func HandleJabber(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	return handleJabber(ctx, newJabberServer(conn), md, logger, h)
}

func handleJabber(ctx context.Context, server *jabberServer, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	conn := server.conn
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("jabber", conn, md, helpers.FirstOrEmpty[parsedJabber](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close jabber connection", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	tlsErr := func(err error) error {
		logger.Debug("TLS handshake failed", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}

	// XMPP clients speak first. Direct TLS (tcp/5223) starts with a handshake
	// record; anything else is treated as a plaintext stream.
	first, err := server.r.Peek(1)
	if err != nil {
		logger.Debug("Failed to read data", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	if first[0] == 0x16 {
		if err := server.startTLS(); err != nil {
			return tlsErr(err)
		}
	}

	writeErr := func(err error) error {
		logger.Error("Failed to write data", slog.String("protocol", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
		return nil
	}

	streamOpen := false
	for range jabberMaxFrames {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "jabber"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		st, err := server.read()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "jabber"), producer.ErrAttr(err))
			if errors.Is(err, jabber.ErrMalformed) || errors.Is(err, errJabberFrameTooLarge) {
				if streamOpen {
					condition := "not-well-formed"
					if errors.Is(err, errJabberFrameTooLarge) {
						condition = "policy-violation"
					}
					if err := server.write("stream-error", "", condition, jabber.StreamError(condition)); err != nil {
						return writeErr(err)
					}
				}
				return nil
			}
			endReason = connection.EndReasonFromRead(err)
			return nil
		}

		if !streamOpen && st.Name != "stream" {
			// RFC 6120 4.9.1.3: open a stream, then send the error.
			if err := server.write("stream", jabberDefaultHost, "", jabber.StreamHeader(server.newStreamID(), jabberDefaultHost)); err != nil {
				return writeErr(err)
			}
			if err := server.write("stream-error", "", "not-well-formed", jabber.StreamError("not-well-formed")); err != nil {
				return writeErr(err)
			}
			return nil
		}

		switch st.Name {
		case "stream":
			streamOpen = true
			from := st.To
			if from == "" {
				from = jabberDefaultHost
			}
			if host, port, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
				logger.Info("jabber stream",
					slog.String("protocol", "jabber"),
					slog.String("handler", "jabber"),
					slog.String("src_ip", host),
					slog.String("src_port", port),
					slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
					slog.String("to", st.To),
					slog.Bool("tls", server.tls),
				)
			}
			if err := server.write("stream", from, "", jabber.StreamHeader(server.newStreamID(), from)); err != nil {
				return writeErr(err)
			}
			if err := server.write("features", "", "", jabber.Features(!server.tls)); err != nil {
				return writeErr(err)
			}

		case "starttls":
			if server.tls {
				if err := server.write("stream-error", "", "policy-violation", jabber.StreamError("policy-violation")); err != nil {
					return writeErr(err)
				}
				return nil
			}
			if err := server.write("proceed", "", "proceed", jabber.Proceed()); err != nil {
				return writeErr(err)
			}
			if err := server.startTLS(); err != nil {
				return tlsErr(err)
			}
			// The client restarts the stream over TLS.
			streamOpen = false

		case "auth":
			if st.Mechanism != "PLAIN" {
				if err := server.write("failure", "", "invalid-mechanism", jabber.SASLFailure("invalid-mechanism")); err != nil {
					return writeErr(err)
				}
				continue
			}
			ev := server.events[len(server.events)-1]
			logger.Info("jabber login",
				slog.String("protocol", "jabber"),
				slog.String("mechanism", st.Mechanism),
				slog.String("username", ev.Username),
			)
			if err := server.write("failure", "", "not-authorized", jabber.SASLFailure("not-authorized")); err != nil {
				return writeErr(err)
			}
			if err := server.write(jabber.CmdStreamEnd, "", "", jabber.StreamEnd()); err != nil {
				return writeErr(err)
			}
			return nil

		case "iq":
			if st.QueryNS == jabber.NSIQAuth && st.Type == "get" {
				if err := server.write("iq", "", "result", jabber.IQAuthFields(st.ID)); err != nil {
					return writeErr(err)
				}
				continue
			}
			if err := server.write("iq", "", "not-authorized", jabber.IQError(st.ID, "auth", "not-authorized")); err != nil {
				return writeErr(err)
			}
			if st.QueryNS == jabber.NSIQAuth && st.Type == "set" {
				if err := server.write(jabber.CmdStreamEnd, "", "", jabber.StreamEnd()); err != nil {
					return writeErr(err)
				}
				return nil
			}

		case jabber.CmdStreamEnd:
			if err := server.write(jabber.CmdStreamEnd, "", "", jabber.StreamEnd()); err != nil {
				return writeErr(err)
			}
			return nil

		default:
			// message, presence, ... before authentication.
			if err := server.write("stream-error", "", "not-authorized", jabber.StreamError("not-authorized")); err != nil {
				return writeErr(err)
			}
			return nil
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}
