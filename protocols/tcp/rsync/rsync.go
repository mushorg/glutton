// Package rsync parses rsync daemon (rsyncd, tcp/873) protocol lines and
// formats the daemon's replies. The line formats follow rsync 3.2.x
// clientserver.c: a version exchange, then a module name (or an empty line /
// "#list" for the module list), then the AUTHREQD challenge-response.
package rsync

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Greeting is the version line rsync 3.2.x sends on connect: protocol 31.0
// and the auth digests it accepts, strongest first.
const Greeting = "@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n"

// greetingPrefix starts every version line, from server and client alike.
const greetingPrefix = "@RSYNCD: "

// ProtocolError is the daemon's reply when the first client line is not a
// version line; the daemon closes afterwards.
const ProtocolError = "@ERROR: protocol startup error\n"

// PeekLen is how many client bytes LooksLikeGreeting needs.
const PeekLen = len(greetingPrefix)

// Module is one entry of the daemon's module list.
type Module struct {
	Name    string
	Comment string
}

// Modules is the advertised module list. Every module requires auth, so a
// client never gets past AUTHREQD and no transfer is emulated.
var Modules = []Module{
	{Name: "backup", Comment: "Nightly backups"},
	{Name: "www", Comment: "Web root"},
	{Name: "data", Comment: "Shared data"},
}

// LooksLikeGreeting reports whether b starts with an rsync version line.
func LooksLikeGreeting(b []byte) bool {
	return bytes.HasPrefix(b, []byte(greetingPrefix))
}

// ParseGreeting parses a client version line "@RSYNCD: <major>.<minor>
// [digests]". It returns the version and the digest list the client offers
// (protocol 30+ clients), and false when line is not a version line.
func ParseGreeting(line string) (version, digests string, ok bool) {
	rest, found := strings.CutPrefix(trimEOL(line), greetingPrefix)
	if !found {
		return "", "", false
	}
	version, digests, _ = strings.Cut(strings.TrimSpace(rest), " ")
	major, _, hasDot := strings.Cut(version, ".")
	if !hasDot || major == "" || strings.Trim(major, "0123456789") != "" {
		return "", "", false
	}
	return version, strings.TrimSpace(digests), true
}

// IsListRequest reports whether a module line asks for the module list.
func IsListRequest(line string) bool {
	line = trimEOL(line)
	return line == "" || line == "#list"
}

// ModuleName returns the module a client line asks for. Clients send the
// bare module name; anything after a '/' is a path inside it.
func ModuleName(line string) string {
	name, _, _ := strings.Cut(trimEOL(line), "/")
	return name
}

// HasModule reports whether name is an advertised module.
func HasModule(name string) bool {
	for _, m := range Modules {
		if m.Name == name {
			return true
		}
	}
	return false
}

// ModuleList is the daemon's reply to a list request: one "%-15s\t%s" line
// per module, then "@RSYNCD: EXIT".
func ModuleList() []byte {
	var b strings.Builder
	for _, m := range Modules {
		fmt.Fprintf(&b, "%-15s\t%s\n", m.Name, m.Comment)
	}
	b.WriteString(greetingPrefix + "EXIT\n")
	return []byte(b.String())
}

// NewChallenge returns an auth challenge as rsync formats it: 16 bytes,
// base64 without padding.
func NewChallenge(r io.Reader) (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

// AuthRequired asks the client to authenticate for a module.
func AuthRequired(challenge string) []byte {
	return []byte(greetingPrefix + "AUTHREQD " + challenge + "\n")
}

// ParseAuth splits the client's "<user> <response>" reply to AUTHREQD. The
// response is the base64 digest of the password and the challenge.
func ParseAuth(line string) (user, response string) {
	user, response, _ = strings.Cut(trimEOL(line), " ")
	return user, strings.TrimSpace(response)
}

// AuthFailed is the daemon's reply to a wrong auth response.
func AuthFailed(module string) []byte {
	return []byte("@ERROR: auth failed on module " + module + "\n")
}

// UnknownModule is the daemon's reply to a module it does not export.
func UnknownModule(name string) []byte {
	return []byte("@ERROR: Unknown module '" + name + "'\n")
}

// trimEOL drops the line terminator; rsync accepts "\n" and "\r\n".
func trimEOL(line string) string {
	return strings.TrimRight(line, "\r\n")
}
