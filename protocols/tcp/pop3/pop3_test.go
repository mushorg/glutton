package pop3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCommand(t *testing.T) {
	require.Equal(t, Command{Verb: "USER", Arg: "bob"}, ParseCommand("user bob\r\n"))
	require.Equal(t, Command{Verb: "QUIT"}, ParseCommand("QUIT\r\n"))
	require.Equal(t, Command{}, ParseCommand("\r\n"))
	// A TLS ClientHello split at 0x0a is binary, not a verb.
	require.Equal(t, Command{}, ParseCommand("\x16\x03\x01\x00\xee\x01\x00\x00\xea\x03\x03\n"))
	require.Equal(t, Command{}, ParseCommand("\x00\x9c\x00\x9d\x00/\x005\xc0\x12\x00\n"))
}

func TestRespond(t *testing.T) {
	require.Equal(t, "+OK", Respond(Command{Verb: "USER", Arg: "x"}, false).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "PASS", Arg: "x"}, false).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "STAT"}, false).Status)
	require.Equal(t, "-ERR", Respond(Command{Verb: "BOGUS"}, false).Status)
	require.Contains(t, string(Respond(Command{Verb: "CAPA"}, false).Data), "USER\r\n")
	require.True(t, Respond(Command{Verb: "QUIT"}, false).Close)
	require.False(t, Respond(Command{Verb: "NOOP"}, false).Close)
}

func TestRespondSTLS(t *testing.T) {
	require.Contains(t, string(Respond(Command{Verb: "CAPA"}, false).Data), "\r\nSTLS\r\n")
	require.NotContains(t, string(Respond(Command{Verb: "CAPA"}, true).Data), "STLS")
	require.Equal(t, Reply{Status: "+OK", Data: []byte("+OK Begin TLS negotiation now.\r\n")}, Respond(Command{Verb: "STLS"}, false))
	require.Equal(t, Reply{Status: "-ERR", Data: []byte("-ERR TLS is already active.\r\n")}, Respond(Command{Verb: "STLS"}, true))
}
