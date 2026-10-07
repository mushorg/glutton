package smtp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		line string
		want Command
	}{
		{"HELO example.com\r\n", Command{Verb: "HELO", Arg: "example.com"}},
		{"ehlo scanner\r\n", Command{Verb: "EHLO", Arg: "scanner"}},
		{"data\r\n", Command{Verb: "DATA"}},
		{"\r\n", Command{}},
		{"MAIL FROM:<alice@example.com>\r\n", Command{Verb: "MAIL", Arg: "FROM:<alice@example.com>", HasPath: true, Mailbox: "alice@example.com"}},
		{"MAIL FROM:<alice@example.com> SIZE=10 BODY=8BITMIME\r\n", Command{
			Verb: "MAIL", Arg: "FROM:<alice@example.com> SIZE=10 BODY=8BITMIME",
			HasPath: true, Mailbox: "alice@example.com", Params: "SIZE=10 BODY=8BITMIME",
		}},
		{"mail from: <a@b.c>\r\n", Command{Verb: "MAIL", Arg: "from: <a@b.c>", HasPath: true, Mailbox: "a@b.c"}},
		{"MAIL FROM:<>\r\n", Command{Verb: "MAIL", Arg: "FROM:<>", HasPath: true}},
		{"RCPT TO:bob@example.org\r\n", Command{Verb: "RCPT", Arg: "TO:bob@example.org", HasPath: true, Mailbox: "bob@example.org"}},
		{"rcpt to:<bob@example.org> NOTIFY=NEVER\r\n", Command{
			Verb: "RCPT", Arg: "to:<bob@example.org> NOTIFY=NEVER",
			HasPath: true, Mailbox: "bob@example.org", Params: "NOTIFY=NEVER",
		}},
		{"RCPT TO:<unterminated\r\n", Command{Verb: "RCPT", Arg: "TO:<unterminated"}},
		{"MAIL garbage\r\n", Command{Verb: "MAIL", Arg: "garbage"}},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			require.Equal(t, tt.want, ParseCommand(tt.line))
		})
	}
}

func TestValidPath(t *testing.T) {
	require.True(t, ParseCommand("MAIL FROM:<example@example.com>").ValidPath())
	require.True(t, ParseCommand("mail from:<example@example.com> SIZE=1").ValidPath())
	require.True(t, ParseCommand("MAIL FROM:<>").ValidPath())
	require.False(t, ParseCommand("MAIL FROM:<example.com>").ValidPath())
	require.True(t, ParseCommand("RCPT TO:<example@example.com>").ValidPath())
	require.False(t, ParseCommand("RCPT TO:<>").ValidPath())
	require.False(t, ParseCommand("RCPT TO:<example.com>").ValidPath())
	require.False(t, ParseCommand("RCPT example@example.com").ValidPath())
}

func TestStatus(t *testing.T) {
	require.Equal(t, "250", Status("250 OK"))
	require.Equal(t, "250", Status("250-PIPELINING\r\n250 HELP"))
	require.Equal(t, "", Status("25"))
	require.Equal(t, "", Status("OK 250"))
}

func TestReply(t *testing.T) {
	require.Equal(t, "250 OK", Reply(250, "OK"))
	require.Equal(t, "250-a\r\n250-b\r\n250 c", Reply(250, "a", "b", "c"))
	require.Equal(t, "334", Reply(334))
}

func TestDecodeAuth(t *testing.T) {
	user, ok := DecodePlain("AGFkbWluAGh1bnRlcjI=") // "\x00admin\x00hunter2"
	require.True(t, ok)
	require.Equal(t, "admin", user)

	_, ok = DecodePlain("YWRtaW4=") // "admin", no NULs
	require.False(t, ok)
	_, ok = DecodePlain("!!!")
	require.False(t, ok)

	user, ok = DecodeLogin("YWRtaW4=\r\n")
	require.True(t, ok)
	require.Equal(t, "admin", user)
	_, ok = DecodeLogin("*")
	require.False(t, ok)
}

func TestClientName(t *testing.T) {
	require.Equal(t, "example.com", ClientName("example.com"))
	require.Equal(t, "User", ClientName("  User extra words "))
	require.Equal(t, "ab", ClientName("a\rb\x00"))
	require.Equal(t, "[1.2.3.4]", ClientName("[1.2.3.4]"))
	require.Len(t, ClientName(strings.Repeat("x", 200)), maxClientName)
	require.Equal(t, "", ClientName(""))
}
