// Package pop3 parses POP3 command lines (RFC 1939) and formats replies.
package pop3

import "strings"

// Greeting is the +OK line a server-first POP3 session opens with: on
// connect for plaintext tcp/110, after the TLS handshake for POP3S. The
// catch-all banner for port 110 reuses it so both share one persona.
const Greeting = "+OK Dovecot (Ubuntu) ready.\r\n"

// Command is one parsed client command line.
type Command struct {
	// Verb is the upper-cased command verb (USER, PASS, CAPA, ...).
	Verb string
	// Arg is everything after the verb with surrounding whitespace removed.
	Arg string
}

// ParseCommand parses a client command line. Verbs are case-insensitive. A
// verb with non-printable bytes (binary data such as a stray TLS record) is
// not a command, so it parses as the empty Command.
func ParseCommand(line string) Command {
	line = strings.TrimSpace(line)
	verb, arg, _ := strings.Cut(line, " ")
	if !printable(verb) {
		return Command{}
	}
	return Command{Verb: strings.ToUpper(verb), Arg: strings.TrimSpace(arg)}
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// Reply is a server response and whether it ends the session.
type Reply struct {
	Status string // "+OK" or "-ERR"
	Data   []byte
	Close  bool
}

// Capabilities is the CAPA reply. It advertises USER/PASS only, so credential
// guessers keep talking, and STLS (RFC 2595) until TLS is active, as Dovecot
// does.
func Capabilities(tls bool) string {
	stls := "STLS\r\n"
	if tls {
		stls = ""
	}
	return "+OK\r\nCAPA\r\nTOP\r\n" + stls + "USER\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\n.\r\n"
}

// Respond builds the reply to cmd; tls reports whether the session is
// already encrypted. PASS is always refused. A +OK reply to STLS means the
// caller must start the TLS handshake next.
func Respond(cmd Command, tls bool) Reply {
	switch cmd.Verb {
	case "CAPA":
		return ok(Capabilities(tls))
	case "STLS":
		if tls {
			return errReply("-ERR TLS is already active.\r\n")
		}
		return ok("+OK Begin TLS negotiation now.\r\n")
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
