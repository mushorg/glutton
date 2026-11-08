package pcanywhere

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommand(t *testing.T) {
	require.Equal(t, NameQuery, Command([]byte("NQ")))
	require.Equal(t, StatusQuery, Command([]byte("ST")))
	require.Equal(t, NameQuery, Command([]byte("NQ\r\n")))
	for _, in := range []string{"", "N", "NQX", "nq", "MGLNDD_1.2.3.4_5632\n"} {
		require.Empty(t, Command([]byte(in)), in)
	}
}

func TestReplyName(t *testing.T) {
	out, status := Reply(NameQuery, DefaultPersona)
	require.Equal(t, "NR", status)
	require.Len(t, out, 2+nameLen+capsLen)
	require.Equal(t, "NRACCT-PC01_______________AHM_3___", string(out))
}

func TestReplyNameTruncatesLongPersona(t *testing.T) {
	out, _ := Reply(NameQuery, Persona{Name: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Caps: "123456789"})
	require.Equal(t, "NRABCDEFGHIJKLMNOPQRSTUVWX12345678", string(out))
}

func TestReplyStatus(t *testing.T) {
	out, status := Reply(StatusQuery, DefaultPersona)
	require.Equal(t, "available", status)
	require.Equal(t, "ST", string(out[:2]))
	require.Equal(t, byte(StatusAvailable), out[4], "status byte is the third after ST")
}

func TestReplyUnknown(t *testing.T) {
	out, status := Reply("", DefaultPersona)
	require.Nil(t, out)
	require.Empty(t, status)
}
