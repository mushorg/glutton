// Package imap parses IMAP4rev1 command lines (RFC 3501) and formats the
// replies of a Dovecot server that refuses every login.
package imap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Persona strings. The server name matches the pop3 greeting so both mail
// handlers look like the same Dovecot install.
const (
	baseCaps = "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+"
	authCaps = "AUTH=PLAIN AUTH=LOGIN"
)

// Capabilities lists the pre-login capabilities; STARTTLS is offered only on
// a plaintext connection.
func Capabilities(tls bool) string {
	if tls {
		return baseCaps + " " + authCaps
	}
	return baseCaps + " STARTTLS " + authCaps
}

// Greeting is the untagged OK a server-first IMAP session opens with: on
// connect for tcp/143, after the TLS handshake for IMAPS.
func Greeting(tls bool) string {
	return "* OK [CAPABILITY " + Capabilities(tls) + "] Dovecot (Ubuntu) ready.\r\n"
}

// Continuation prompts.
const (
	LiteralContinue = "+ OK\r\n"
	SASLContinue    = "+ \r\n"
	// AUTHENTICATE LOGIN prompts are base64 "Username:" and "Password:".
	LoginUserPrompt = "+ VXNlcm5hbWU6\r\n"
	LoginPassPrompt = "+ UGFzc3dvcmQ6\r\n"
)

// Command is one parsed client command.
type Command struct {
	Tag  string
	Verb string // upper-cased
	Args []string
}

// ErrNoTag is returned for a line without a tag and command.
var ErrNoTag = errors.New("imap command without tag")

// LiteralSize reports whether line ends with a literal marker {n} or {n+}
// (LITERAL+), returning its size and whether the client waits for a
// continuation.
func LiteralSize(line []byte) (n int, sync, ok bool) {
	line = bytes.TrimRight(line, "\r\n")
	if !bytes.HasSuffix(line, []byte("}")) {
		return 0, false, false
	}
	open := bytes.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false, false
	}
	num := string(line[open+1 : len(line)-1])
	sync = !strings.HasSuffix(num, "+")
	n, err := strconv.Atoi(strings.TrimSuffix(num, "+"))
	if err != nil || n < 0 {
		return 0, false, false
	}
	return n, sync, true
}

// ParseCommand parses a complete command, literals included. Arguments are
// atoms, quoted strings (unescaped), literals, or parenthesized lists kept
// as written.
func ParseCommand(data []byte) (Command, error) {
	s := strings.TrimRight(string(data), "\r\n")
	tag, rest, _ := strings.Cut(s, " ")
	verb, rest, _ := strings.Cut(rest, " ")
	if tag == "" || verb == "" {
		return Command{}, ErrNoTag
	}
	return Command{Tag: tag, Verb: strings.ToUpper(verb), Args: parseArgs(rest)}, nil
}

func parseArgs(s string) []string {
	var args []string
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			return args
		}
		var arg string
		switch s[0] {
		case '"':
			arg, s = quoted(s[1:])
		case '{':
			arg, s = literal(s)
		case '(':
			arg, s = list(s)
		default:
			end := strings.IndexAny(s, " \r\n")
			if end < 0 {
				end = len(s)
			}
			arg, s = s[:end], s[end:]
		}
		args = append(args, arg)
	}
}

func quoted(s string) (string, string) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:]
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), ""
}

func literal(s string) (string, string) {
	end := strings.Index(s, "}")
	if end < 0 {
		return s, ""
	}
	n, err := strconv.Atoi(strings.TrimSuffix(s[1:end], "+"))
	rest := strings.TrimPrefix(s[end+1:], "\r\n")
	if err != nil || n < 0 {
		return s[:end+1], rest
	}
	n = min(n, len(rest))
	return rest[:n], rest[n:]
}

func list(s string) (string, string) {
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && inQuote:
			i++
		case c == '"':
			inQuote = !inQuote
		case c == '(' && !inQuote:
			depth++
		case c == ')' && !inQuote:
			depth--
			if depth == 0 {
				return s[:i+1], s[i+1:]
			}
		}
	}
	return s, ""
}

// DecodePlain decodes a SASL PLAIN response (authzid NUL authcid NUL passwd).
func DecodePlain(b64 string) (username, password string, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return "", "", errors.New("malformed SASL PLAIN response")
	}
	return parts[1], parts[2], nil
}

// DecodeBase64 decodes one AUTHENTICATE LOGIN response line.
func DecodeBase64(line string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	return string(raw), err
}

// Reply is a server response, its status (the tagged condition, or "+" for a
// continuation) and whether it ends the session.
type Reply struct {
	Status string
	Data   []byte
	Close  bool
}

// Tagged formats a tagged response with condition cond (OK, NO or BAD).
func Tagged(tag, cond, text string) Reply {
	return Reply{Status: cond, Data: []byte(tag + " " + cond + " " + text + "\r\n")}
}

// AuthFailed is Dovecot's reply to a wrong password.
func AuthFailed(tag string) Reply {
	return Tagged(tag, "NO", "[AUTHENTICATIONFAILED] Authentication failed.")
}

// AuthAborted answers a "*" SASL response.
func AuthAborted(tag string) Reply {
	return Tagged(tag, "BAD", "Authentication aborted by client.")
}

// BadCommand answers a line without a tag.
func BadCommand() Reply {
	return Reply{Status: "BAD", Data: []byte("* BAD Error in IMAP command received by server.\r\n")}
}

// Respond builds the reply to every command except AUTHENTICATE and a
// STARTTLS that is accepted, which need the connection.
func Respond(cmd Command, tls bool) Reply {
	switch cmd.Verb {
	case "CAPABILITY":
		r := Tagged(cmd.Tag, "OK", "Pre-login capabilities listed, post-login capabilities have more.")
		r.Data = append([]byte("* CAPABILITY "+Capabilities(tls)+"\r\n"), r.Data...)
		return r
	case "NOOP":
		return Tagged(cmd.Tag, "OK", "NOOP completed.")
	case "ID":
		r := Tagged(cmd.Tag, "OK", "ID completed.")
		r.Data = append([]byte("* ID (\"name\" \"Dovecot\")\r\n"), r.Data...)
		return r
	case "LOGIN":
		if len(cmd.Args) < 2 {
			return Tagged(cmd.Tag, "BAD", "Error in IMAP command LOGIN: Missing arguments.")
		}
		return AuthFailed(cmd.Tag)
	case "STARTTLS":
		if tls {
			return Tagged(cmd.Tag, "BAD", "TLS is already active.")
		}
		return Tagged(cmd.Tag, "OK", "Begin TLS negotiation now.")
	case "LOGOUT":
		r := Tagged(cmd.Tag, "OK", "Logout completed.")
		r.Data = append([]byte("* BYE Logging out\r\n"), r.Data...)
		r.Close = true
		return r
	case "SELECT", "EXAMINE", "LIST", "LSUB", "STATUS", "CREATE", "DELETE", "RENAME",
		"SUBSCRIBE", "UNSUBSCRIBE", "APPEND", "FETCH", "STORE", "SEARCH", "COPY", "UID",
		"CLOSE", "EXPUNGE", "CHECK", "IDLE", "NAMESPACE", "ENABLE", "GETQUOTAROOT":
		return Tagged(cmd.Tag, "BAD", "Error in IMAP command "+cmd.Verb+": Command not permitted in this state.")
	}
	return Tagged(cmd.Tag, "BAD", "Error in IMAP command received by server.")
}
