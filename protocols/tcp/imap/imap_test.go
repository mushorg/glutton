package imap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGreeting(t *testing.T) {
	require.Equal(t, "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.\r\n", Greeting(false))
	require.NotContains(t, Greeting(true), "STARTTLS")
}

func TestParseCommand(t *testing.T) {
	cmd, err := ParseCommand([]byte("a1 login \"ad\\\"min\" pass123\r\n"))
	require.NoError(t, err)
	require.Equal(t, Command{Tag: "a1", Verb: "LOGIN", Args: []string{"ad\"min", "pass123"}}, cmd)

	cmd, err = ParseCommand([]byte("a2 LOGIN {4}\r\nuser {5+}\r\np w x\r\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"user", "p w x"}, cmd.Args)

	cmd, err = ParseCommand([]byte("a3 ID (\"name\" \"a (b)\" \"x\" NIL)\r\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"(\"name\" \"a (b)\" \"x\" NIL)"}, cmd.Args)

	cmd, err = ParseCommand([]byte("a4 CAPABILITY\r\n"))
	require.NoError(t, err)
	require.Equal(t, Command{Tag: "a4", Verb: "CAPABILITY"}, cmd)

	_, err = ParseCommand([]byte("\r\n"))
	require.ErrorIs(t, err, ErrNoTag)
	_, err = ParseCommand([]byte("CAPABILITY\r\n"))
	require.ErrorIs(t, err, ErrNoTag)
}

func TestLiteralSize(t *testing.T) {
	n, sync, ok := LiteralSize([]byte("a LOGIN {12}\r\n"))
	require.Equal(t, []any{12, true, true}, []any{n, sync, ok})
	n, sync, ok = LiteralSize([]byte("a LOGIN {3+}\r\n"))
	require.Equal(t, []any{3, false, true}, []any{n, sync, ok})
	_, _, ok = LiteralSize([]byte("a LOGIN user pass\r\n"))
	require.False(t, ok)
	_, _, ok = LiteralSize([]byte("a LOGIN {x}\r\n"))
	require.False(t, ok)
}

func TestDecodePlain(t *testing.T) {
	user, pass, err := DecodePlain("AGFkbWluAHNlY3JldA==") // \0admin\0secret
	require.NoError(t, err)
	require.Equal(t, "admin", user)
	require.Equal(t, "secret", pass)
	_, _, err = DecodePlain("YWRtaW4=")
	require.Error(t, err)
	_, _, err = DecodePlain("!!")
	require.Error(t, err)
}

func TestRespond(t *testing.T) {
	r := Respond(Command{Tag: "a1", Verb: "LOGIN", Args: []string{"u", "p"}}, false)
	require.Equal(t, "NO", r.Status)
	require.Equal(t, "a1 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", string(r.Data))

	r = Respond(Command{Tag: "a2", Verb: "LOGOUT"}, false)
	require.True(t, r.Close)
	require.Equal(t, "* BYE Logging out\r\na2 OK Logout completed.\r\n", string(r.Data))

	r = Respond(Command{Tag: "a3", Verb: "CAPABILITY"}, true)
	require.Equal(t, "OK", r.Status)
	require.True(t, strings.HasPrefix(string(r.Data), "* CAPABILITY IMAP4rev1 "))
	require.NotContains(t, string(r.Data), "STARTTLS")

	require.Equal(t, "BAD", Respond(Command{Tag: "a4", Verb: "STARTTLS"}, true).Status)
	require.Equal(t, "OK", Respond(Command{Tag: "a4", Verb: "STARTTLS"}, false).Status)
	require.Equal(t, "BAD", Respond(Command{Tag: "a5", Verb: "LOGIN", Args: []string{"u"}}, false).Status)
	require.Equal(t, "BAD", Respond(Command{Tag: "a6", Verb: "SELECT"}, false).Status)
	require.Equal(t, "BAD", Respond(Command{Tag: "a7", Verb: "XYZZY"}, false).Status)
}
