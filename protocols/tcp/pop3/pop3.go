// Package pop3 parses POP3 command lines (RFC 1939) and formats replies.
package pop3

import "strings"

// Greeting is the +OK line sent once the TLS handshake completes.
const Greeting = "+OK Dovecot ready.\r\n"

// Command is one parsed client command line.
type Command struct {
	// Verb is the upper-cased command verb (USER, PASS, CAPA, ...).
	Verb string
	// Arg is everything after the verb with surrounding whitespace removed.
	Arg string
}

// ParseCommand parses a client command line. Verbs are case-insensitive.
func ParseCommand(line string) Command {
	line = strings.TrimSpace(line)
	verb, arg, _ := strings.Cut(line, " ")
	return Command{Verb: strings.ToUpper(verb), Arg: strings.TrimSpace(arg)}
}

// Reply is a server response and whether it ends the session.
type Reply struct {
	Status string // "+OK" or "-ERR"
	Data   []byte
	Close  bool
}

// capabilities advertises USER/PASS only, so credential guessers keep talking.
var capabilities = "+OK\r\nCAPA\r\nTOP\r\nUSER\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\n.\r\n"

// Respond builds the reply to cmd. PASS is always refused.
func Respond(cmd Command) Reply {
	switch cmd.Verb {
	case "CAPA":
		return ok(capabilities)
	case "USER":
		return ok("+OK\r\n")
	case "PASS":
		return errReply("-ERR [AUTH] Authentication failed.\r\n")
	case "QUIT":
		r := ok("+OK Logging out.\r\n")
		r.Close = true
		return r
	case "NOOP":
		return ok("+OK\r\n")
	case "AUTH", "APOP":
		return errReply("-ERR [AUTH] Authentication failed.\r\n")
	case "STAT", "LIST", "UIDL", "RETR", "DELE", "TOP", "RSET":
		return errReply("-ERR Not logged in.\r\n")
	}
	return errReply("-ERR Unknown command.\r\n")
}

func ok(s string) Reply       { return Reply{Status: "+OK", Data: []byte(s)} }
func errReply(s string) Reply { return Reply{Status: "-ERR", Data: []byte(s)} }
