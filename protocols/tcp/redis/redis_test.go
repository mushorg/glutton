package redis

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func read(t *testing.T, in string) (Command, error) {
	t.Helper()
	return ReadCommand(bufio.NewReader(strings.NewReader(in)), MaxRequestLen)
}

func TestReadCommandMultibulk(t *testing.T) {
	// nmap's redis-server service probe
	in := "*1\r\n$4\r\ninfo\r\n"
	cmd, err := read(t, in)
	require.NoError(t, err)
	require.Equal(t, []byte(in), cmd.Raw)
	require.Equal(t, [][]byte{[]byte("info")}, cmd.Args)
	require.False(t, cmd.Inline)
	require.Equal(t, "info", cmd.Name())
}

func TestReadCommandPipelined(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("*1\r\n$8\r\nFLUSHALL\r\n*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n"))
	cmd, err := ReadCommand(r, MaxRequestLen)
	require.NoError(t, err)
	require.Equal(t, "flushall", cmd.Name())
	cmd, err = ReadCommand(r, MaxRequestLen)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("config"), []byte("set"), []byte("dir"), []byte("/var/spool/cron/")}, cmd.Args)
	_, err = ReadCommand(r, MaxRequestLen)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadCommandBinaryBulk(t *testing.T) {
	// bulk strings are length-delimited, so CR/LF inside a value is data
	cmd, err := read(t, "*3\r\n$3\r\nset\r\n$1\r\nx\r\n$8\r\n\n\n*/1\r\n\n\r\n")
	require.NoError(t, err)
	require.Equal(t, []byte("\n\n*/1\r\n\n"), cmd.Args[2])
}

func TestReadCommandInline(t *testing.T) {
	in := "config set dir \"/root/.ssh\" 'it''s'\r\n"
	_, err := read(t, in)
	var pe *ProtocolError
	require.ErrorAs(t, err, &pe, "a quote must be followed by a space")
	require.Equal(t, "unbalanced quotes in request", pe.Msg)

	in = "set x \"\\n\\n*/1 * * * * id\\x41\\n\" '\\'q'\n"
	cmd, err := read(t, in)
	require.NoError(t, err)
	require.True(t, cmd.Inline)
	require.Equal(t, []byte(in), cmd.Raw)
	require.Equal(t, [][]byte{[]byte("set"), []byte("x"), []byte("\n\n*/1 * * * * idA\n"), []byte("'q")}, cmd.Args)
}

func TestReadCommandEmpty(t *testing.T) {
	cmd, err := read(t, "\r\n")
	require.NoError(t, err)
	require.Empty(t, cmd.Args)
	require.Equal(t, "", cmd.Name())

	cmd, err = read(t, "*0\r\n")
	require.NoError(t, err)
	require.Empty(t, cmd.Args)
}

func TestReadCommandProtocolErrors(t *testing.T) {
	for in, msg := range map[string]string{
		"*x\r\n":                 "invalid multibulk length",
		"*1\r\n+info\r\n":        "expected '$', got '+'",
		"*1\r\n$-3\r\n":          "invalid bulk length",
		"*1\r\n$abc\r\n":         "invalid bulk length",
		"set \"unterminated\r\n": "unbalanced quotes in request",
	} {
		cmd, err := read(t, in)
		var pe *ProtocolError
		require.ErrorAs(t, err, &pe, in)
		require.Equal(t, msg, pe.Msg, in)
		require.Equal(t, []byte(in), cmd.Raw, in)
	}
}

func TestReadCommandCaps(t *testing.T) {
	// a bulk longer than the cap reads up to it
	in := "*1\r\n$100\r\n" + strings.Repeat("A", 100) + "\r\n"
	cmd, err := ReadCommand(bufio.NewReader(strings.NewReader(in)), 32)
	require.ErrorIs(t, err, ErrTooLong)
	require.Equal(t, []byte(in[:32]), cmd.Raw)

	// an inline line without a newline stops at the cap
	cmd, err = ReadCommand(bufio.NewReader(strings.NewReader(strings.Repeat("B", 5000))), 4096)
	require.ErrorIs(t, err, ErrTooLong)
	require.True(t, cmd.Inline)
	require.Len(t, cmd.Raw, 4096)

	// a huge declared length must not overflow
	in = "*1\r\n$9223372036854775807\r\n" + strings.Repeat("C", 40)
	_, err = ReadCommand(bufio.NewReader(strings.NewReader(in)), 32)
	require.ErrorIs(t, err, ErrTooLong)

	_, err = read(t, "*100000\r\n")
	require.ErrorIs(t, err, ErrTooLong)
}

func TestReadCommandCutOff(t *testing.T) {
	in := "*2\r\n$4\r\necho\r\n$10\r\nhel"
	cmd, err := read(t, in)
	require.True(t, errors.Is(err, io.ErrUnexpectedEOF), err)
	require.Equal(t, []byte(in), cmd.Raw)
}

func TestLooksLikeRESP(t *testing.T) {
	for _, in := range []string{"*1\r\n$4\r\ninfo\r\n", "*1\r\n$", "*12\r\n$3\r\n"} {
		require.True(t, LooksLikeRESP([]byte(in)), in)
	}
	for _, in := range []string{
		"*1\r\n",         // too short to see the bulk marker
		"*0\r\n$",        // empty array
		"*\r\n$4",        // no count
		"*1\r\n:4\r\n",   // not a bulk
		"* 1\r\n$4\r\n",  // not a count
		"INFO\r\n",       // inline commands are too ambiguous off-port
		"*1234567\r\n$4", // count longer than any request we accept
	} {
		require.False(t, LooksLikeRESP([]byte(in)), in)
	}
}

func TestReplies(t *testing.T) {
	require.Equal(t, Reply{Data: []byte("+OK\r\n"), Status: "OK"}, Simple("OK"))
	require.Equal(t, Reply{Data: []byte("-NOSCRIPT No matching script.\r\n"), Status: "NOSCRIPT"}, Error("NOSCRIPT No matching script."))
	require.Equal(t, Reply{Data: []byte(":-2\r\n"), Status: StatusInteger}, Integer(-2))
	require.Equal(t, Reply{Data: []byte("$0\r\n\r\n"), Status: StatusBulk}, Bulk(nil))
	require.Equal(t, Reply{Data: []byte("$-1\r\n"), Status: StatusNil}, Nil())
	require.Equal(t, Reply{Data: []byte("*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n"), Status: StatusArray}, Array("dir", "/tmp"))
	require.Equal(t, Reply{Data: []byte("*0\r\n"), Status: StatusArray}, Array())
	require.Equal(t, Reply{Data: []byte("*2\r\n$1\r\n0\r\n*1\r\n$1\r\nx\r\n"), Status: StatusArray}, Scan("0", []string{"x"}))
}

func TestErrorReplies(t *testing.T) {
	require.Equal(t, "-ERR unknown command `system.exec`, with args beginning with: `id`, \r\n",
		string(UnknownCommand([][]byte{[]byte("system.exec"), []byte("id")}).Data))
	require.Equal(t, "-ERR unknown command `hello`, with args beginning with: \r\n",
		string(UnknownCommand([][]byte{[]byte("hello")}).Data))
	// client input quoted in an error cannot break the reply line
	require.Equal(t, "-ERR unknown command `a  b`, with args beginning with: \r\n",
		string(UnknownCommand([][]byte{[]byte("a\r\nb")}).Data))
	require.Equal(t, "-ERR wrong number of arguments for 'get' command\r\n", string(WrongArity("get").Data))
	require.Equal(t, "-ERR Unknown subcommand or wrong number of arguments for 'docs'. Try COMMAND HELP.\r\n",
		string(UnknownSubcommand("command", "docs").Data))
	require.Equal(t, "-ERR Protocol error: invalid bulk length\r\n",
		string(ProtocolErrorReply(&ProtocolError{Msg: "invalid bulk length"}).Data))
}
