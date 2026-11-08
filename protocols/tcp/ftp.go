package tcp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	// 1xx
	StatusFileStatusOK = 150 // RFC 959, 4.2.1
	// 2xx
	StatusOK                 = 200 // RFC 959, 4.2.1
	StatusServiceReady       = 220 // RFC 959, 4.2.1
	StatusClosingControlConn = 221 // RFC 959, 4.2.1
	StatusClosingDataConn    = 226 // RFC 959, 4.2.1
	StatusSystemType         = 215 // RFC 959, 4.2.1
	StatusUserLoggedIn       = 230 // RFC 959, 4.2.1
	StatusAuthOK             = 234 // RFC 4217, 4
	StatusFileActionOK       = 250 // RFC 959, 4.2.1
	StatusPathCreated        = 257 // RFC 959, 4.2.1
	// 3xx
	StatusUserOK = 331 // RFC 959, 4.2.1
	// 4xx
	StatusCannotOpenDataConnection = 425 // RFC 959, 4.2.1
	// 5xx
	StatusSyntaxError       = 500 // RFC 959, 4.2.1
	StatusSyntaxErrorInArgs = 501 // RFC 959, 4.2.1
	StatusNotImplemented    = 502 // RFC 959, 4.2.1
	StatusParamNotImpl      = 504 // RFC 959, 4.2.1
	StatusActionNotTaken    = 550 // RFC 959, 4.2.1
)

type parsedFTP struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	Path        string `json:"path,omitempty"`
	Username    string `json:"username,omitempty"` // USER argument
	Password    string `json:"password,omitempty"` // PASS argument
	Status      string `json:"status,omitempty"`
	ServerName  string `json:"server_name,omitempty"` // SNI of an in-session ClientHello (command "tls")
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"` // command line cut at maxFTPLine
}

const (
	// maxFTPLine caps one command line (RFC 959 servers allow far less).
	maxFTPLine = 8 << 10
	// maxFTPFrames caps the frames kept per connection; the session ends with
	// max_frames once it is reached.
	maxFTPFrames = 1000
)

type ftpServer struct {
	events []parsedFTP
	conn   net.Conn
	reader *bufio.Reader
	w      io.Writer
	tls    bool
}

type ftpResponse struct {
	code int
	msg  string
}

// maxFTPVerb bounds a verb: RFC 959 and its extensions use 3-4 letters; the
// slack lets HTTP or SMTP verbs sent to tcp/21 still show up.
const maxFTPVerb = 8

// ftpVerb reports whether s looks like a command verb (ASCII letters only),
// so binary input such as a TLS record never ends up in command.
func ftpVerb(s string) bool {
	if len(s) == 0 || len(s) > maxFTPVerb {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func ftpVerbAndPath(msg string) (cmd, path string) {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) == 0 || !ftpVerb(fields[0]) {
		return "", ""
	}
	cmd = strings.ToUpper(fields[0])
	if len(fields) > 1 && (cmd == "STOR" || cmd == "RETR" || cmd == "CWD") {
		path = fields[1]
	}
	return cmd, path
}

// ftpArg returns everything after the verb with the line ending and
// surrounding whitespace removed, so arguments with spaces stay intact.
func ftpArg(msg string) string {
	_, arg, _ := strings.Cut(strings.TrimSpace(msg), " ")
	return strings.TrimSpace(arg)
}

func (s *ftpServer) read(_ interfaces.Logger, _ interfaces.Honeypot) (string, error) {
	line, truncated, err := helpers.ReadLine(s.reader, maxFTPLine)
	msg := string(line)
	if err != nil {
		return msg, err
	}
	cmd, path := ftpVerbAndPath(msg)
	frame := parsedFTP{
		Direction: "read",
		Command:   cmd,
		Path:      path,
		Payload:   line,
		Truncated: truncated,
	}
	switch cmd {
	case "USER":
		frame.Username = ftpArg(msg)
	case "PASS":
		frame.Password = ftpArg(msg)
	}
	s.events = append(s.events, frame)
	return msg, nil
}

func (s *ftpServer) write(resp ftpResponse) error {
	msg := fmt.Sprintf("%d %s\r\n", resp.code, resp.msg)
	_, err := s.w.Write([]byte(msg))
	if err != nil {
		return err
	}
	s.events = append(s.events, parsedFTP{
		Direction: "write",
		Status:    strconv.Itoa(resp.code),
		Payload:   []byte(msg),
	})
	return nil
}

// tlsNext reports whether the next client bytes open a TLS handshake record.
func (s *ftpServer) tlsNext() (bool, error) {
	first, err := s.reader.Peek(1)
	if err != nil {
		return false, err
	}
	if first[0] != 0x16 {
		return false, nil
	}
	hdr, _ := s.reader.Peek(3)
	return helpers.LooksLikeTLSHandshakeRecord(hdr), nil
}

// startTLS runs a server TLS handshake over the buffered reader and switches
// the control connection to it. The client's handshake bytes are recorded as
// a "tls" read frame and the TLS details go on md for the produced event.
func (s *ftpServer) startTLS(md *connection.Metadata) error {
	tlsConn, info, err := helpers.TerminateTLSFrom(s.conn, s.reader)
	md.TLS = info
	md.AddInner("tls")
	s.events = append(s.events, parsedFTP{
		Direction:  "read",
		Command:    "tls",
		ServerName: info.ServerName,
		Payload:    info.Hello,
		Truncated:  info.Truncated,
	})
	if err != nil {
		return err
	}
	s.tls = true
	s.reader = bufio.NewReader(tlsConn)
	s.w = tlsConn
	return nil
}

// ftpReply answers the verbs the main loop does not act on. Verbs real
// servers know but this one does not emulate (PASV, LIST, RETR, FEAT, ...)
// get 502; anything else, including binary input with no verb, gets 500 as
// on vsftpd or ProFTPD instead of a uniform 200.
func ftpReply(cmd, arg string, tlsActive bool) ftpResponse {
	switch cmd {
	case "SYST":
		return ftpResponse{StatusSystemType, "UNIX Type: L8"}
	case "PWD", "XPWD":
		return ftpResponse{StatusPathCreated, `"/" is the current directory`}
	case "CWD", "CDUP":
		return ftpResponse{StatusFileActionOK, "Directory successfully changed."}
	case "TYPE":
		return ftpResponse{StatusOK, "Switching to Binary mode."}
	case "NOOP":
		return ftpResponse{StatusOK, "NOOP ok."}
	case "AUTH":
		switch strings.ToUpper(arg) {
		case "TLS", "SSL", "TLS-C", "TLS-P":
			if tlsActive {
				return ftpResponse{StatusNotImplemented, "Already using TLS."}
			}
			return ftpResponse{StatusAuthOK, "Proceed with negotiation."}
		}
		return ftpResponse{StatusParamNotImpl, "Unknown AUTH type."}
	case "PBSZ":
		return ftpResponse{StatusOK, "PBSZ=0"}
	case "PROT":
		return ftpResponse{StatusOK, "PROT now Private."}
	case "ABOR", "ACCT", "ALLO", "APPE", "DELE", "EPRT", "EPSV", "FEAT", "HELP", "LIST",
		"MDTM", "MKD", "MLSD", "MLST", "MODE", "NLST", "OPTS", "PASV", "REIN", "REST",
		"RETR", "RMD", "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "STAT", "STOU", "STRU":
		return ftpResponse{StatusNotImplemented, "Command not implemented."}
	}
	return ftpResponse{StatusSyntaxError, "Syntax error, command unrecognized."}
}

// parseFTPPort parses a PORT argument (h1,h2,h3,h4,p1,p2) into the client's
// data address.
func parseFTPPort(arg string) (string, error) {
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		return "", errors.New("PORT needs six comma-separated numbers")
	}
	var b [6]int
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v > 255 {
			return "", fmt.Errorf("PORT field %q is not a byte", p)
		}
		b[i] = v
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	return net.JoinHostPort(ip, strconv.Itoa(b[4]<<8|b[5])), nil
}

func (s *ftpServer) ftpSTOR(addr string, path string) (ftpResponse, string) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return ftpResponse{StatusCannotOpenDataConnection, "Failed to establish connection."}, ""
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return ftpResponse{StatusActionNotTaken, "Failed to establish connection."}, ""
	}
	buffer := make([]byte, maxBufferSize)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ftpResponse{StatusActionNotTaken, "Failed to read file."}, ""
	}

	buffer = buffer[:n]
	fileHash, err := helpers.Store(buffer, filepath.Join("payloads", "ftp"))
	if err != nil {
		return ftpResponse{StatusActionNotTaken, "Failed to store file."}, ""
	}

	s.events = append(s.events, parsedFTP{
		Direction:   "read",
		Command:     "STOR",
		Path:        path,
		PayloadHash: fileHash,
		Payload:     buffer,
	})
	return ftpResponse{StatusClosingDataConn, "File received."}, fileHash
}

// HandleFTP takes a net.Conn and does basic FTP communication
func HandleFTP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := ftpServer{
		conn:   conn,
		reader: bufio.NewReader(conn),
		w:      conn,
		tls:    md.TLS != nil,
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("ftp", conn, md, helpers.FirstOrEmpty[parsedFTP](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce events", slog.String("protocol", "ftp"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close FTP connection", slog.String("protocol", "ftp"), producer.ErrAttr(err))
		}
	}()

	host, srcPort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	if err := server.write(ftpResponse{StatusServiceReady, "Welcome"}); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	var dataAddr string // from the last valid PORT
loop:
	for {
		if len(server.events) >= maxFTPFrames {
			endReason = connection.EndMaxFrames
			break
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "ftp"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		// A ClientHello on the control connection (an implicit-FTPS client on
		// tcp/21 that read the banner first): terminate TLS over the buffered
		// reader and greet again, as pop3.go does.
		if !server.tls {
			isTLS, err := server.tlsNext()
			if err != nil {
				logger.Debug("Failed to read data", slog.String("protocol", "ftp"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				break
			}
			if isTLS {
				if err := server.startTLS(&md); err != nil {
					logger.Debug("Failed TLS handshake", slog.String("protocol", "ftp"), producer.ErrAttr(err))
					endReason = connection.EndReasonFromRead(err)
					break
				}
				if err := server.write(ftpResponse{StatusServiceReady, "Welcome"}); err != nil {
					endReason = connection.EndWriteError
					return err
				}
				continue
			}
		}
		msg, err := server.read(logger, h)
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "ftp"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
		if len(msg) < 4 {
			continue
		}
		cmd, path := ftpVerbAndPath(msg)

		logger.Info(
			"ftp command received",
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", srcPort),
			slog.String("message", fmt.Sprintf("%q", msg)),
			slog.String("handler", "ftp"),
		)

		var (
			resp     ftpResponse
			filehash string
		)
		switch cmd {
		case "USER":
			resp = ftpResponse{StatusUserOK, "Ok."}
		case "PASS":
			resp = ftpResponse{StatusUserLoggedIn, "Ok."}
		case "STOR":
			if dataAddr == "" {
				resp = ftpResponse{StatusCannotOpenDataConnection, "Use PORT or PASV first."}
				break
			}
			if err := server.write(ftpResponse{StatusFileStatusOK, "Ok to send data."}); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			resp, filehash = server.ftpSTOR(dataAddr, path)
			if filehash != "" {
				logger.Info(
					"FTP payload receievd",
					slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
					slog.String("src_ip", host),
					slog.String("src_port", srcPort),
					slog.String("handler", "ftp"),
					slog.String("payload_hash", filehash),
				)
			}
		case "QUIT":
			if err := server.write(ftpResponse{StatusClosingControlConn, "Goodbye."}); err != nil {
				endReason = connection.EndWriteError
				return err
			}
			break loop
		case "PORT":
			addr, err := parseFTPPort(ftpArg(msg))
			if err != nil {
				dataAddr = ""
				resp = ftpResponse{StatusSyntaxErrorInArgs, "Illegal PORT command."}
				break
			}
			dataAddr = addr
			resp = ftpResponse{StatusOK, "PORT command successful."}
		default:
			resp = ftpReply(cmd, ftpArg(msg), server.tls)
		}
		if err := server.write(resp); err != nil {
			endReason = connection.EndWriteError
			return err
		}
		if resp.code == StatusAuthOK {
			if err := server.startTLS(&md); err != nil {
				logger.Debug("Failed AUTH TLS handshake", slog.String("protocol", "ftp"), producer.ErrAttr(err))
				endReason = connection.EndReasonFromRead(err)
				break
			}
		}
	}
	return nil
}
