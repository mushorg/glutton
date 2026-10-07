// Package smtp parses SMTP command lines (RFC 5321) and formats replies.
package smtp

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// mailboxRE is a naive address check: something@something.
var mailboxRE = regexp.MustCompile(`^.+@.+$`)

// Command is one parsed client command line.
type Command struct {
	// Verb is the upper-cased command verb (HELO, MAIL, RCPT, ...).
	Verb string
	// Arg is everything after the verb with surrounding whitespace removed.
	Arg string
	// HasPath is set for MAIL FROM: and RCPT TO: lines that carry a path.
	HasPath bool
	// Mailbox is the address from the MAIL FROM:/RCPT TO: path, without angle brackets.
	Mailbox string
	// Params holds the ESMTP parameters after the path (SIZE=, BODY=, NOTIFY=, ...).
	Params string
}

// ParseCommand parses a client command line. The verb ends at the first space
// or colon, so "MAIL FROM:<a@b>" and "mail from: <a@b>" both give MAIL.
func ParseCommand(line string) Command {
	line = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if line == "" {
		return Command{}
	}
	verb, arg := line, ""
	if idx := strings.IndexAny(line, " :"); idx >= 0 {
		verb, arg = line[:idx], line[idx:]
	}
	cmd := Command{Verb: strings.ToUpper(verb), Arg: strings.TrimSpace(arg)}
	switch cmd.Verb {
	case "MAIL":
		cmd.parsePath("FROM:")
	case "RCPT":
		cmd.parsePath("TO:")
	}
	return cmd
}

// parsePath fills Mailbox and Params from an argument like "FROM:<a@b> SIZE=10".
// The keyword is matched case-insensitively and a space after the colon is
// tolerated. A bare address without angle brackets is accepted as well.
func (c *Command) parsePath(keyword string) {
	if len(c.Arg) < len(keyword) || !strings.EqualFold(c.Arg[:len(keyword)], keyword) {
		return
	}
	rest := strings.TrimSpace(c.Arg[len(keyword):])
	if strings.HasPrefix(rest, "<") {
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return
		}
		c.HasPath = true
		c.Mailbox = rest[1:end]
		c.Params = strings.TrimSpace(rest[end+1:])
		return
	}
	mailbox, params, _ := strings.Cut(rest, " ")
	if mailbox == "" {
		return
	}
	c.HasPath = true
	c.Mailbox = mailbox
	c.Params = strings.TrimSpace(params)
}

// ValidPath reports whether a MAIL or RCPT command carries an acceptable path.
// MAIL FROM:<> (the null reverse-path used for bounces) is accepted.
func (c Command) ValidPath() bool {
	if !c.HasPath {
		return false
	}
	if c.Verb == "MAIL" && c.Mailbox == "" {
		return true
	}
	return mailboxRE.MatchString(c.Mailbox)
}

// Status returns the 3-digit reply code at the start of a reply, or "".
func Status(reply string) string {
	if len(reply) < 3 {
		return ""
	}
	for i := 0; i < 3; i++ {
		if reply[i] < '0' || reply[i] > '9' {
			return ""
		}
	}
	return reply[:3]
}

// Reply formats a reply without the trailing CRLF. More than one line gives a
// multi-line reply: every line but the last uses "code-" as its prefix.
func Reply(code int, lines ...string) string {
	if len(lines) == 0 {
		return strconv.Itoa(code)
	}
	c := strconv.Itoa(code)
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(c)
		if i < len(lines)-1 {
			b.WriteByte('-')
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(line)
	}
	return b.String()
}

// maxClientName bounds the HELO/EHLO argument echoed back in a reply.
const maxClientName = 64

// ClientName returns the HELO/EHLO argument in a form that is safe to echo in
// a reply: the first word only, printable ASCII, at most maxClientName bytes.
func ClientName(arg string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(arg), " ")
	name = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, name)
	if len(name) > maxClientName {
		name = name[:maxClientName]
	}
	return name
}

// DecodeLogin decodes one base64 line of an AUTH LOGIN exchange.
func DecodeLogin(line string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// DecodePlain decodes an AUTH PLAIN response (RFC 4616,
// authzid NUL authcid NUL passwd) and returns the authentication identity.
// The password is not returned.
func DecodePlain(line string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return "", false
	}
	parts := bytes.SplitN(raw, []byte{0}, 3)
	if len(parts) != 3 {
		return "", false
	}
	return string(parts[1]), true
}
