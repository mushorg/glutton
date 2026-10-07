package pop3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCommand(t *testing.T) {
	require.Equal(t, Command{Verb: "USER", Arg: "bob"}, ParseCommand("user bob\r\n"))
	require.Equal(t, Command{Verb: "QUIT"}, ParseCommand("QUIT\r\n"))
	require.Equal(t, Command{}, ParseCommand("\r\n"))
}

func TestRespond(t *testing.T) {
	require.Equal(t, "+OK", Respond(Command{Verb: "USER", Arg: "x"}).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "PASS", Arg: "x"}).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "STAT"}).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "BOGUS"}).Status)
	require.Contains(t, string(Respond(Command{Verb: "CAPA"}).Data), "USER\r\n")
	require.True(t, Respond(Command{Verb: "QUIT"}).Close)
	require.False(t, Respond(Command{Verb: "NOOP"}).Close)
}
